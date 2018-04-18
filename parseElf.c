#include <linux/stat.h>
#include <linux/slab.h>
#include "parseElf.h"
#include "fileOps.h"
#include "mapper.h"

extern void fd_install(unsigned int fd, struct file *file);
extern int get_unused_fd_flags(unsigned flags);
//extern unsigned long cur;

Elf_obj *elf_open(char *filename){
	int i, fd;
	struct file* elf_file;
	struct kstat sbuf;
	Elf_obj *ep;
	Elf64_Shdr *shdr;
	char *buf;

	if ((ep = (Elf_obj *)kmalloc(sizeof(Elf_obj), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "Malloc failed\n");
		return NULL;
	}

	/* Do some consistency checks on the binary */
	elf_file = file_open(filename, O_CREAT, O_RDONLY);
	if (elf_file == NULL) {
		printk(KERN_ERR "Can't open %s\n", filename);
		return NULL;
	}

	fd = get_unused_fd_flags(O_CREAT);
	//fsnotify_open(elf_file);
	fd_install(fd, elf_file);	
	
	printk("elf_file fd = %d\n", fd);
	if (vfs_fstat(fd, &sbuf) == -1) {
		printk(KERN_ERR "Can't stat %s\n", filename);
		return NULL;
	}
	
	if (sbuf.size < sizeof(Elf64_Ehdr)) {
		printk(KERN_ERR "\"%s\" is not an ELF binary object\n",	filename);
		return NULL;
	}

	/* It looks OK, so map the Elf binary into our address space */
	ep->mlen = sbuf.size;
	buf = kmalloc(ep->mlen, GFP_KERNEL);
	file_read(elf_file, 0, buf, ep->mlen);
	ep->maddr = buf;
	//ep->maddr = do_mmap(NULL, ep->mlen, PROT_READ, MAP_SHARED, fd, 0);
	if (ep->maddr == (void *)-1) {
		printk(KERN_ERR "Can't mmap %s\n", filename);
		return NULL;
	}
	file_close(elf_file);

	/* The Elf binary begins with the Elf header */
	ep->ehdr = ep->maddr;

	/* Make sure that this is an Elf binary */ 
	if (strncmp(ep->ehdr->e_ident, ELFMAG, SELFMAG)) {
		printk(KERN_ERR "%s is not an ELF binary object\n",	filename);
		return NULL;
	}

	/* 
	* Find the static and dynamic symbol tables and their string
	* tables in the the mapped binary. The sh_link field in symbol
	* table section headers gives the section index of the string
	* table for that symbol table.
	*/
	shdr = (Elf64_Shdr *)(ep->maddr + ep->ehdr->e_shoff);
	for (i = 0; i < ep->ehdr->e_shnum; i++) {
	if (shdr[i].sh_type == SHT_SYMTAB) {   /* Static symbol table */
	    ep->symtab = (Elf64_Sym *)(ep->maddr + shdr[i].sh_offset);
	    ep->symtab_end = (Elf64_Sym *)((char *)ep->symtab + shdr[i].sh_size);
	    ep->strtab = (char *)(ep->maddr + shdr[shdr[i].sh_link].sh_offset);
	}
	if (shdr[i].sh_type == SHT_DYNSYM) {   /* Dynamic symbol table */
	    ep->dsymtab = (Elf64_Sym *)(ep->maddr + shdr[i].sh_offset);
	    ep->dsymtab_end = (Elf64_Sym *)((char *)ep->dsymtab + shdr[i].sh_size);
	    ep->dstrtab = (char *)(ep->maddr + shdr[shdr[i].sh_link].sh_offset);
	}
	}
	return ep;	
}

/* 
 * elf_close - Free up the resources of an  elf object
 */
void elf_close(Elf_obj *ep) 
{
    	kfree(ep->maddr);
	kfree(ep);
}

/*
 * elf_symname - Return ASCII name of a static symbol
 */
char *elf_symname(Elf_obj *ep, Elf64_Sym *sym)
{
    return &ep->strtab[sym->st_name];
}

/*
*elf_symvalue - Return value of a static symbol
*/
unsigned long elf_symvalue(Elf_obj *ep, Elf64_Sym *sym)
{
    //return ep->strtab[sym->st_value];
    return sym->st_value;
}

/*
*elf_symsize - Return size of a static symbol
*/
unsigned long elf_symsize(Elf_obj *ep, Elf64_Sym *sym)
{
    //return ep->strtab[sym->st_size];
    return sym->st_size;
}

/*
 * elf_dsymname - Return ASCII name of a dynamic symbol
 */ 
char *elf_dsymname(Elf_obj *ep, Elf64_Sym *sym)
{
    return &ep->dstrtab[sym->st_name];
}

/*
 * elf_firstsym - Return ptr to first symbol in static symbol table
 */
Elf64_Sym *elf_firstsym(Elf_obj *ep)
{
    return ep->symtab;
}

/*
 * elf_nextsym - Return ptr to next symbol in static symbol table,
 * or NULL if no more symbols.
 */
Elf64_Sym *elf_nextsym(Elf_obj *ep, Elf64_Sym *sym)
{
    sym++;
    if (sym < ep->symtab_end)
	return sym;
    else
	return NULL;
}

/*
 * elf_firstdsym - Return ptr to first symbol in dynamic symbol table
 */
Elf64_Sym *elf_firstdsym(Elf_obj *ep)
{
    return ep->dsymtab;
}

/*
 * elf_nextdsym - Return ptr to next symbol in dynamic symbol table,
 * of NULL if no more symbols.
 */ 
Elf64_Sym *elf_nextdsym(Elf_obj *ep, Elf64_Sym *sym)
{
    sym++;
    if (sym < ep->dsymtab_end)
	return sym;
    else
	return NULL;
}

/*
 * elf_isfunc - Return true if symbol is a static function
 */
int elf_isfunc(Elf_obj *ep, Elf64_Sym *sym) 
{
    return ((ELF32_ST_TYPE(sym->st_info) == STT_FUNC) &&
	    (sym->st_shndx != SHT_NULL));
}

/*
 * elf_isdfunc - Return true if symbol is a dynamic function 
 */
int elf_isdfunc(Elf_obj *ep, Elf64_Sym *sym) 
{
    return ((ELF32_ST_TYPE(sym->st_info) == STT_FUNC));
}

int parse(char *file_name, item_t **mapper){
	char *symname;
	unsigned long ip, size;
	Elf64_Sym *sym;
	Elf_obj *elf_obj = elf_open(file_name);
	int ret = 0;

	if(elf_obj == NULL){
		printk(KERN_ERR "elf_obj open failed\n");
		ret = -1;
		return ret;
	}
	
	sym = elf_firstsym(elf_obj);
	
	do{
		/*
		printk("Symbol name = %-30s, value = %-30lx, size = %-30ld\n", 
			elf_symname(elf_obj, sym),
			elf_symvalue(elf_obj, sym),
			elf_symsize(elf_obj, sym));
		*/
	
		symname = elf_symname(elf_obj, sym);
		size = elf_symsize(elf_obj, sym);
		
		if((symname != NULL) && (size != 0)){
			ip = elf_symvalue(elf_obj, sym);
			ret = insert_mapper(mapper, symname, ip, size);
			if(ret == -1){
				printk(KERN_ERR "insert_mapper failed\n");
				ret = -1;
				return ret;
			}
		}
		sym = elf_nextsym(elf_obj, sym);
	}while(sym);
	
	/*
	unsigned long i;
	for(i = 0; i < (*mapper)->cur; i++){
		item_t *tmp = *mapper + i;
		printk("%-30s, %-30ld, %-30ld\n", tmp->func_name, tmp->ip, tmp->size);
	}
	*/
	
	elf_close(elf_obj);
	return ret;
}