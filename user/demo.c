//
// =========================================================
// x86 Hardware Assisted Virtualization Demo for AMD-V (SVM)
// =========================================================
//
// Description: A very basic driver and associated user app
// that walks through all the steps to do a successful vmrun.
// After vmrun, the guest code does a vmmcall and #vmexits
// back to the host. The guest state mirrors the host.
//
// References for study:
//
// 1. AMD64 Architecture Programmer's Manual
//    (Vol 2: System Programming)
//
// 2. KVM from the Linux kernel
//    (Mostly kvm_main.c, svm.c)
//
// 3. Original Intel VT-x vmlaunch demo
//    (https://github.com/vishmohan/vmlaunch)
//
// 4. Original vmrunsample demo
//    (https://github.com/soulxu/vmrunsample)
//
// Copyright (C) 2017: STROMASYS SA (http://www.stromasys.com)
//
// Authors:
//
// - Elias Kouskoumvekakis <elias.kousl@stromasys.com>
// - Alex Xu (Xu He Jie)   <xuhj@cn.ibm.com> (Original user space code)
//
// This work is licensed under the terms of the GNU GPL, version 2.
// See the LICENSE file in the top-level directory.
//

#include <stdio.h>
#include <memory.h>
#include <sys/mman.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "vmrun.h"

#define VMRUN_DEVICE	"/dev/vmrun"
#define RAM_SIZE	8000000
#define CODE_START	0x1000
#define GUEST_BINARY	"guest.bin"

struct vmrun {
	int dev_fd;
	int vm_fd;
	__u64 ram_size;
	__u64 ram_start;
	int vmrun_version;
	struct vmrun_userspace_memory_region mem;
	struct vcpu *vcpus;
	int vcpu_number;
};

struct vcpu {
	int vcpu_id;
	int vcpu_fd;
	pthread_t vcpu_thread;
	struct vmrun_run *vmrun_run;
	int vmrun_run_mmap_size;
	struct vmrun_regs regs;
	struct vmrun_sregs sregs;
	void *(*vcpu_thread_func)(void *);
};

void vmrun_reset_vcpu (struct vcpu *vcpu)
{
	if (ioctl(vcpu->vcpu_fd, VMRUN_GET_SREGS, &(vcpu->sregs)) < 0) {
		perror("can not get sregs\n");
		exit(1);
	}

	vcpu->sregs.cs.selector = CODE_START;
	vcpu->sregs.cs.base = CODE_START * 16;
	vcpu->sregs.ss.selector = CODE_START;
	vcpu->sregs.ss.base = CODE_START * 16;
	vcpu->sregs.ds.selector = CODE_START;
	vcpu->sregs.ds.base = CODE_START *16;
	vcpu->sregs.es.selector = CODE_START;
	vcpu->sregs.es.base = CODE_START * 16;
	vcpu->sregs.fs.selector = CODE_START;
	vcpu->sregs.fs.base = CODE_START * 16;
	vcpu->sregs.gs.selector = CODE_START;

	if (ioctl(vcpu->vcpu_fd, VMRUN_SET_SREGS, &vcpu->sregs) < 0) {
		perror("can not set sregs");
		exit(1);
	}

	vcpu->regs.rflags = 0x0000000000000002ULL;
	vcpu->regs.rip = 0;
	vcpu->regs.rsp = 0xffffffff;
	vcpu->regs.rbp= 0;

	if (ioctl(vcpu->vcpu_fd, VMRUN_SET_REGS, &(vcpu->regs)) < 0) {
		perror("VMRUN SET REGS\n");
		exit(1);
	}
}

void *vmrun_cpu_thread(void *data)
{
	struct vmrun *vmrun = (struct vmrun *)data;
	int ret = 0;
	vmrun_reset_vcpu(vmrun->vcpus);
	
	while (1) {
		printf("vcpu run\n");
		ret = ioctl(vmrun->vcpus->vcpu_fd, VMRUN_VCPU_RUN, 0);
	
		if (ret < 0) {
			fprintf(stderr, "vcpu run failed\n");
			exit(1);
		}
	
		switch (vmrun->vcpus->vmrun_run->exit_reason) {
		case VMRUN_EXIT_UNKNOWN:
			printf("VMRUN_EXIT_UNKNOWN\n");
			break;
		case VMRUN_EXIT_DEBUG:
			printf("VMRUN_EXIT_DEBUG\n");
			break;
		case VMRUN_EXIT_IO:
			printf("VMRUN_EXIT_IO\n");
			printf("out port: %d, data: %d\n",
				vmrun->vcpus->vmrun_run->io.port,  
				*(int *)((char *)(vmrun->vcpus->vmrun_run) + vmrun->vcpus->vmrun_run->io.data_offset)
				);
			sleep(1);
			break;
		case VMRUN_EXIT_MMIO:
			printf("VMRUN_EXIT_MMIO\n");
			break;
		case VMRUN_EXIT_INTR:
			printf("VMRUN_EXIT_INTR\n");
			break;
		case VMRUN_EXIT_SHUTDOWN:
			printf("VMRUN_EXIT_SHUTDOWN\n");
			goto exit_vmrun;
			break;
		default:
			printf("VMRUN PANIC\n");
			goto exit_vmrun;
		}
	}
	
exit_vmrun:
	return 0;
}

void vmrun_load_binary(struct vmrun *vmrun)
{
	int fd = open(GUEST_BINARY, O_RDONLY);
	
	if (fd < 0) {
		fprintf(stderr, "can not open binary file\n");
		exit(1);
	}
	
	ssize_t ret = 0;
	char *p = (char *)vmrun->ram_start;
	
	while(1) {
		ret = read(fd, p, 4096);

		if (ret <= 0)
			break;

		printf("read size: %d", (int)ret);
		p += ret;
	}
}

struct vmrun *vmrun_init(void)
{
	struct vmrun *vmrun = malloc(sizeof(struct vmrun));
	
	vmrun->dev_fd = open(VMRUN_DEVICE, O_RDWR);
	
	if (vmrun->dev_fd < 0) {
		perror("open vmrun device fault: ");
		return NULL;
	}
	
	return vmrun;
}

void vmrun_clean(struct vmrun *vmrun)
{
	assert (vmrun != NULL);
	close(vmrun->dev_fd);
	free(vmrun);
}

int vmrun_create_vm(struct vmrun *vmrun, int ram_size)
{
	int ret = 0;
	vmrun->vm_fd = ioctl(vmrun->dev_fd, VMRUN_CREATE_VM, 0);
	
	if (vmrun->vm_fd < 0) {
		perror("can not create vm");
		return -1;
	}
	
	vmrun->ram_size = ram_size;
	vmrun->ram_start = (__u64)mmap(NULL,
				       vmrun->ram_size, 
				       PROT_READ | PROT_WRITE,
				       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, 
		                       -1,
				       0);
	
	if ((void *)vmrun->ram_start == MAP_FAILED) {
		perror("can not mmap ram");
		return -1;
	}
	
	vmrun->mem.slot = 0;
	vmrun->mem.guest_phys_addr = 0;
	vmrun->mem.memory_size = vmrun->ram_size;
	vmrun->mem.userspace_addr = vmrun->ram_start;
	
	ret = ioctl(vmrun->vm_fd, VMRUN_SET_USER_MEMORY_REGION, &(vmrun->mem));
	
	if (ret < 0) {
		perror("can not set user memory region");
		return ret;
	}
	
	return ret;
}

void vmrun_clean_vm(struct vmrun *vmrun)
{
	close(vmrun->vm_fd);
	munmap((void *)vmrun->ram_start, vmrun->ram_size);
}

struct vcpu *vmrun_init_vcpu(struct vmrun *vmrun, int vcpu_id, void *(*fn)(void *))
{
	struct vcpu *vcpu = malloc(sizeof(struct vcpu));

	vcpu->vcpu_id = 0;
	vcpu->vcpu_fd = ioctl(vmrun->vm_fd, VMRUN_VCPU_CREATE, vcpu->vcpu_id);

	if (vcpu->vcpu_fd < 0) {
		perror("can not create vcpu");
		return NULL;
	}

	vcpu->vmrun_run_mmap_size = ioctl(vmrun->dev_fd, VMRUN_GET_VCPU_MMAP_SIZE, 0);

	if (vcpu->vmrun_run_mmap_size < 0) {
		perror("can not get vcpu mmsize");
		return NULL;
	}

	printf("%d\n", vcpu->vmrun_run_mmap_size);
	vcpu->vmrun_run = mmap(NULL,
			       vcpu->vmrun_run_mmap_size,
			       PROT_READ | PROT_WRITE,
			       MAP_SHARED,
			       vcpu->vcpu_fd, 0);

	if (vcpu->vmrun_run == MAP_FAILED) {
	perror("can not mmap vmrun_run");
	return NULL;
	}

	vcpu->vcpu_thread_func = fn;
	return vcpu;
}

void vmrun_clean_vcpu(struct vcpu *vcpu)
{
	munmap(vcpu->vmrun_run, vcpu->vmrun_run_mmap_size);
	close(vcpu->vcpu_fd);
}

void vmrun_run_vm(struct vmrun *vmrun)
{
	int i = 0;

	for (i = 0; i < vmrun->vcpu_number; i++) {
		if (pthread_create(&(vmrun->vcpus->vcpu_thread),
				   (const pthread_attr_t *)NULL,
				   vmrun->vcpus[i].vcpu_thread_func,
				   vmrun) != 0){
		    perror("can not create vmrun thread");
		    exit(1);
		}
	}

	pthread_join(vmrun->vcpus->vcpu_thread, NULL);
}

int main(int argc, char **argv)
{
	int ret = 0;
	struct vmrun *vmrun = vmrun_init();

	if (vmrun == NULL) {
		fprintf(stderr, "vmrun init fauilt\n");
		return -1;
	}

	if (vmrun_create_vm(vmrun, RAM_SIZE) < 0) {
		fprintf(stderr, "create vm fault\n");
		return -1;
	}

	vmrun_load_binary(vmrun);

	// We only support one vcpu
	vmrun->vcpu_number = 1;
	vmrun->vcpus = vmrun_init_vcpu(vmrun,
				       0,
				       vmrun_cpu_thread);

	vmrun_run_vm(vmrun);
	vmrun_clean_vm(vmrun);
	vmrun_clean_vcpu(vmrun->vcpus);
	vmrun_clean(vmrun);
}
