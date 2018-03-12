---
title: Linux Slab Allocator
date: 2017-08-03 22:52:56
tags:
- slab
categories:
- kernel_development
---

趁着有空，把linux slab分配机制给看一下。

## What is Slab
内核中小内存分配机制有三种：slab/slub/slob，slab是基础，slub是升级，而slob是一种精简的分配算法，主要用于嵌入式系统。虽然slab会逐渐被slub取代，但是还是有必要了解slab分配器的原理的。
<!-- more -->
直接在网上找了张图(slab分配器的主要结构)，画的真的是不错~~简单明了。(但是这张图有点老了)
<img src="http://of38fq57s.bkt.clouddn.com/slab-cache.gif">
现在的slab：
<img src="http://of38fq57s.bkt.clouddn.com/newslab.PNG">
最高层是cache_chain，这是个slab缓存的链表。其中的每个元素都是kmem_cache结构的引用(称为cache)。
```c
//define in include/linux/slab_def.h
//linux-3.12

struct kmem_cache {
/* 1) Cache tunables. Protected by cache_chain_mutex */
	unsigned int batchcount;
	unsigned int limit;
	unsigned int shared;

	unsigned int size;
	u32 reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

	unsigned int flags;		/* constant flags */
	unsigned int num;		/* # of objs per slab */

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t allocflags;

	size_t colour;			/* cache colouring range */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *slabp_cache;
	unsigned int slab_size;

	/* constructor func */
	void (*ctor)(void *obj);

/* 4) cache creation/removal */
	const char *name;
	struct list_head list;
	int refcount;
	int object_size;
	int align;

/* 5) statistics */
#ifdef CONFIG_DEBUG_SLAB
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;

	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
#endif /* CONFIG_DEBUG_SLAB */
#ifdef CONFIG_MEMCG_KMEM
	struct memcg_cache_params *memcg_params;
#endif

/* 6) per-cpu/per-node data, touched during every alloc/free */
	/*
	 * We put array[] at the end of kmem_cache, because we want to size
	 * this array to nr_cpu_ids slots instead of NR_CPUS
	 * (see kmem_cache_init())
	 * We still use [NR_CPUS] and not [1] or [0] because cache_cache
	 * is statically defined, so we reserve the max number of cpus.
	 *
	 * We also need to guarantee that the list is able to accomodate a
	 * pointer for each node since "nodelists" uses the remainder of
	 * available pointers.
	 */
	struct kmem_cache_node **node;   //kmem_list3
	struct array_cache *array[NR_CPUS + MAX_NUMNODES];
	/*
	 * Do not add fields after array[]
	 */
};

//define in linux/mm/slab.h
/*
 * The slab lists for all objects.
 */
struct kmem_cache_node {
	spinlock_t list_lock;

#ifdef CONFIG_SLAB
	struct list_head slabs_partial;	/* partial list first, better asm code */
	struct list_head slabs_full;
	struct list_head slabs_free;
	unsigned long free_objects;
	unsigned int free_limit;
	unsigned int colour_next;	/* Per-node cache coloring */
	struct array_cache *shared;	/* shared per node */
	struct array_cache **alien;	/* on other nodes */
	unsigned long next_reap;	/* updated without locking */
	int free_touched;		/* updated without locking */
#endif

#ifdef CONFIG_SLUB
	unsigned long nr_partial;
	struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
#endif
#endif

};

//define in mm/slab.c
struct array_cache {
	unsigned int avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int touched;
	spinlock_t lock;
	void *entry[];	/*
			 * Must have this definition in here for the proper
			 * alignment of array_cache. Also simplifies accessing
			 * the entries.
			 *
			 * Entries should not be directly dereferenced as
			 * entries belonging to slabs marked pfmemalloc will
			 * have the lower bits set SLAB_OBJ_PFMEMALLOC
			 */
};

struct slab {
	union {
		struct {
			struct list_head list;
			unsigned long colouroff;
			void *s_mem;		/* including colour offset */
			unsigned int inuse;	/* num of objs active in slab */
			kmem_bufctl_t free;
			unsigned short nodeid;
		};
		struct slab_rcu __slab_cover_slab_rcu;
	};
};
```

每个缓存中都包含了一个slabs列表，有三种slab(由一个或多个物理上的连续的页组成)：
1. slab_full，完全分配的slab。
2. slab_partial，部分分配的slab。
3. slab_empty，空slab，或者没有对象被分配。

由于对象是从slab中进行分配和释放的，因此单个slab可以在slab列表之间进行移动。例如，当一个slab 中的所有对象都被使用完时，就从slabs_partial列表中移动到slabs_full列表中。当一个slab 完全被分配并且有对象被释放后，就从slabs_full列表中移动到slabs_partial 列表中。当所有对象都被释放之后，就从slabs_partial列表移动到slabs_empty列表中。

还有就是slab着色，开始不怎么懂.....现在也不怎么懂，反正就是为了提高效率而设计的~~
通过以下命令我们可以看到系统的slab状态：
```
cat /proc/slabinfo
```
我们可以看到2种类型的slab，像tcp，udp之类的专用slab，也有kmalloc-8，kmalloc-16...dma-kmalloc-96，dma-kmalloc-192...这些都是普通slab。

其具体工作原理要搞清还好是挺费劲的，这里只是简单了解以下，待下次遇到相应的slab overflow再来仔细探讨。

## And Slub
slub分配器跟slab分配器总的来说原理相差不是很大。可以看看这篇[博文](http://www.cnblogs.com/tolimit/p/4654109.html)。

## Links
[linux内存源码分析 - SLAB分配器概述](http://www.cnblogs.com/tolimit/p/4566189.html)
[Linux slab 分配器剖析](https://www.ibm.com/developerworks/cn/linux/l-linux-slab-allocator/)
