/*
 * inittialization
 */
struct kvm_vcpu_pv_apf_data {
        __u32 reason;
        __u8 pad[60];
        __u32 enabled;
};

static DEFINE_PER_CPU(struct kvm_vcpu_pv_apf_data, apf_reason) __aligned(64);

void __cpuinit kvm_guest_cpu_init(void)
{
    if (!kvm_para_available())
            return;

    if (kvm_para_has_feature(KVM_FEATURE_ASYNC_PF) && kvmapf) {
            u64 pa = __pa(&__get_cpu_var(apf_reason));
            wrmsrl(MSR_KVM_ASYNC_PF_EN, pa | KVM_ASYNC_PF_ENABLED);
            __get_cpu_var(apf_reason).enabled = 1;
            printk(KERN_INFO"KVM setup async PF for cpu %d\n",
                   smp_processor_id());
}


/**
 * ve handler
 */
#ifdef CONFIG_KVM_GUEST
ENTRY(async_page_fault)
	RING0_EC_FRAME
	pushl $do_async_page_fault
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC
END(apf_page_fault)
#endif

#ifdef CONFIG_KVM_GUEST
errorentry async_page_fault do_async_page_fault
#endif

u32 kvm_read_and_reset_pf_reason(void)
{
	u32 reason = 0;

	if (__get_cpu_var(apf_reason).enabled) {
		reason = __get_cpu_var(apf_reason).reason;
		__get_cpu_var(apf_reason).reason = 0;
	}

	return reason;
}
EXPORT_SYMBOL_GPL(kvm_read_and_reset_pf_reason);

void kvm_async_pf_task_wait(u32 token)
{
	u32 key = hash_32(token, KVM_TASK_SLEEP_HASHBITS);
	struct kvm_task_sleep_head *b = &async_pf_sleepers[key];
	struct kvm_task_sleep_node n, *e;
	DEFINE_WAIT(wait);

	spin_lock(&b->lock);
	e = _find_apf_task(b, token);
	if (e) {
		/* dummy entry exist -> wake up was delivered ahead of PF */
		hlist_del(&e->link);
		kfree(e);
		spin_unlock(&b->lock);
		return;
	}

	n.token = token;
	n.cpu = smp_processor_id();
	init_waitqueue_head(&n.wq);
	hlist_add_head(&n.link, &b->list);
	spin_unlock(&b->lock);

	for (;;) {
		prepare_to_wait(&n.wq, &wait, TASK_UNINTERRUPTIBLE);
		if (hlist_unhashed(&n.link))
			break;
		local_irq_enable();
		schedule();
		local_irq_disable();
	}
	finish_wait(&n.wq, &wait);

	return;
}
EXPORT_SYMBOL_GPL(kvm_async_pf_task_wait);

static void apf_task_wake_one(struct kvm_task_sleep_node *n)
{
	hlist_del_init(&n->link);
	if (waitqueue_active(&n->wq))
		wake_up(&n->wq);
}

static void apf_task_wake_all(void)
{
	int i;

	for (i = 0; i < KVM_TASK_SLEEP_HASHSIZE; i++) {
		struct hlist_node *p, *next;
		struct kvm_task_sleep_head *b = &async_pf_sleepers[i];
		spin_lock(&b->lock);
		hlist_for_each_safe(p, next, &b->list) {
			struct kvm_task_sleep_node *n =
				hlist_entry(p, typeof(*n), link);
			if (n->cpu == smp_processor_id())
				apf_task_wake_one(n);
		}
		spin_unlock(&b->lock);
	}
}

void kvm_async_pf_task_wake(u32 token)
{
	u32 key = hash_32(token, KVM_TASK_SLEEP_HASHBITS);
	struct kvm_task_sleep_head *b = &async_pf_sleepers[key];
	struct kvm_task_sleep_node *n;

	if (token == ~0) {
		apf_task_wake_all();
		return;
	}

again:
	spin_lock(&b->lock);
	n = _find_apf_task(b, token);
	if (!n) {
		/*
		 * async PF was not yet handled.
		 * Add dummy entry for the token.
		 */
		n = kmalloc(sizeof(*n), GFP_ATOMIC);
		if (!n) {
			/*
			 * Allocation failed! Busy wait while other cpu
			 * handles async PF.
			 */
			spin_unlock(&b->lock);
			cpu_relax();
			goto again;
		}
		n->token = token;
		n->cpu = smp_processor_id();
		init_waitqueue_head(&n->wq);
		hlist_add_head(&n->link, &b->list);
	} else
		apf_task_wake_one(n);
	spin_unlock(&b->lock);
	return;
}
EXPORT_SYMBOL_GPL(kvm_async_pf_task_wake);

dotraplinkage void __kprobes
do_async_page_fault(struct pt_regs *regs, unsigned long error_code)
{
	switch (kvm_read_and_reset_pf_reason()) {
	default:
		do_page_fault(regs, error_code);
		break;
	case KVM_PV_REASON_PAGE_NOT_PRESENT:
		/* page is swapped out by the host. */
		kvm_async_pf_task_wait((u32)read_cr2());
		break;
	case KVM_PV_REASON_PAGE_READY:
		kvm_async_pf_task_wake((u32)read_cr2());
		break;
	}
}
