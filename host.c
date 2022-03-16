/*
 * emulate msr write to support guest initializatiosupport 
 */
static int kvm_pv_enable_async_pf(struct kvm_vcpu *vcpu, u64 data)
{
	gpa_t gpa = data & ~0x3f;

	/* Bits 1:5 are resrved, Should be zero */
	if (data & 0x3e)
		return 1;

	vcpu->arch.apf.msr_val = data;

	if (!(data & KVM_ASYNC_PF_ENABLED)) {
		kvm_clear_async_pf_completion_queue(vcpu);
		kvm_async_pf_hash_reset(vcpu);
		return 0;
	}

	if (kvm_gfn_to_hva_cache_init(vcpu->kvm, &vcpu->arch.apf.data, gpa))
		return 1;

	kvm_async_pf_wakeup_all(vcpu);
	return 0;
}

int kvm_set_msr_common(struct kvm_vcpu *vcpu, u32 msr, u64 data)
 {
 	switch (msr) {
	case MSR_KVM_ASYNC_PF_EN:
	if (kvm_pv_enable_async_pf(vcpu, data))
			return 1;
}

/*
 * initialization
 */
static void async_pf_execute(struct work_struct *work)
{
	struct page *page = NULL;
	struct kvm_async_pf *apf =
		container_of(work, struct kvm_async_pf, work);
	struct mm_struct *mm = apf->mm;
	struct kvm_vcpu *vcpu = apf->vcpu;
	unsigned long addr = apf->addr;
	gva_t gva = apf->gva;

	might_sleep();

	use_mm(mm);
	down_read(&mm->mmap_sem);
	get_user_pages(current, mm, addr, 1, 1, 0, &page, NULL);
	up_read(&mm->mmap_sem);
	unuse_mm(mm);

	spin_lock(&vcpu->async_pf.lock);
	list_add_tail(&apf->link, &vcpu->async_pf.done);
	apf->page = page;
	apf->done = true;
	spin_unlock(&vcpu->async_pf.lock);

	/*
	 * apf may be freed by kvm_check_async_pf_completion() after
	 * this point
	 */

	trace_kvm_async_pf_completed(addr, page, gva);

	if (waitqueue_active(&vcpu->wq))
		wake_up_interruptible(&vcpu->wq);

	mmdrop(mm);
	kvm_put_kvm(vcpu->kvm);
}

void kvm_arch_async_page_not_present(struct kvm_vcpu *vcpu,
				     struct kvm_async_pf *work)
{
	trace_kvm_async_pf_not_present(work->gva);

	kvm_make_request(KVM_REQ_APF_HALT, vcpu);
	kvm_add_async_pf_gfn(vcpu, work->arch.gfn);
}

int kvm_setup_async_pf(struct kvm_vcpu *vcpu, gva_t gva, gfn_t gfn,
		       struct kvm_arch_async_pf *arch)
{
	struct kvm_async_pf *work;

	if (vcpu->async_pf.queued >= ASYNC_PF_PER_VCPU)
		return 0;

	/* setup delayed work */

	/*
	 * do alloc nowait since if we are going to sleep anyway we
	 * may as well sleep faulting in page
	 */
	work = kmem_cache_zalloc(async_pf_cache, GFP_NOWAIT);
	if (!work)
		return 0;

	work->page = NULL;
	work->done = false;
	work->vcpu = vcpu;
	work->gva = gva;
	work->addr = gfn_to_hva(vcpu->kvm, gfn);
	work->arch = *arch;
	work->mm = current->mm;
	atomic_inc(&work->mm->mm_count);
	kvm_get_kvm(work->vcpu->kvm);

	/* this can't really happen otherwise gfn_to_pfn_async
	   would succeed */
	if (unlikely(kvm_is_error_hva(work->addr)))
		goto retry_sync;

	INIT_WORK(&work->work, async_pf_execute);
	if (!schedule_work(&work->work))
		goto retry_sync;

	list_add_tail(&work->queue, &vcpu->async_pf.queue);
	vcpu->async_pf.queued++;
	kvm_arch_async_page_not_present(vcpu, work);
	return 1;
retry_sync:
	kvm_put_kvm(work->vcpu->kvm);
	mmdrop(work->mm);
	kmem_cache_free(async_pf_cache, work);
	return 0;
}


int kvm_arch_setup_async_pf(struct kvm_vcpu *vcpu, gva_t gva, gfn_t gfn)
{
	struct kvm_arch_async_pf arch;
	arch.gfn = gfn;

	return kvm_setup_async_pf(vcpu, gva, gfn, &arch);
}

static bool try_async_pf(struct kvm_vcpu *vcpu, gfn_t gfn, gva_t gva,
			 pfn_t *pfn)
{
	bool async;

	*pfn = gfn_to_pfn_async(vcpu->kvm, gfn, &async);

	if (!async)
		return false; /* *pfn has correct page already */

	put_page(pfn_to_page(*pfn));

	if (can_do_async_pf(vcpu)) {
		trace_kvm_try_async_get_page(async, *pfn);
		if (kvm_find_async_pf_gfn(vcpu, gfn)) {
			trace_kvm_async_pf_doublefault(gva, gfn);
			kvm_make_request(KVM_REQ_APF_HALT, vcpu);
			return true;
		} else if (kvm_arch_setup_async_pf(vcpu, gva, gfn))
			return true;
	}

	*pfn = gfn_to_pfn(vcpu->kvm, gfn);

	return false;
}

void kvm_arch_async_page_present(struct kvm_vcpu *vcpu,
				 struct kvm_async_pf *work)
{
	trace_kvm_async_pf_ready(work->gva);
	kvm_del_async_pf_gfn(vcpu, work->arch.gfn);
}

void kvm_check_async_pf_completion(struct kvm_vcpu *vcpu)
{
	struct kvm_async_pf *work;

	if (list_empty_careful(&vcpu->async_pf.done))
		return;

	spin_lock(&vcpu->async_pf.lock);
	work = list_first_entry(&vcpu->async_pf.done, typeof(*work), link);
	list_del(&work->link);
	spin_unlock(&vcpu->async_pf.lock);

	kvm_arch_async_page_present(vcpu, work);

	list_del(&work->queue);
	vcpu->async_pf.queued--;
	if (work->page)
		put_page(work->page);
	kmem_cache_free(async_pf_cache, work);
}
