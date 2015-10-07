#include <common.h>
#include <coov4.h>
#include <list.h>
#include <map.h>
#include <osal.h>

#define IDENTIFIER_LEN 5
#define MIN(A,B) (A) > (B) ? (B) : (A)

List SingleLinkedList_new(OE oe);

static int isws(char c) {
	if (c == ' ' || c == '\t') return 1;
	return 0;
}


typedef enum _jrcp_op_ {
	JRCP_ERROR,JRCP_XOR,JRCP_AND,JRCP_XNOR
} JRCPOp;

typedef struct _jrcp_exp_ {
	JRCPOp op;
	char l[IDENTIFIER_LEN];
	char r[IDENTIFIER_LEN];
} * JRCPExp;

JRCPExp JRCPExp_New(OE oe, const char * l, JRCPOp op,const char * r) {
	JRCPExp exp = (JRCPExp)oe->getmem(sizeof(*exp));
	uint ll=0,lr=0;
	if (!exp) return 0;

	while(l[ll++]);
	while(r[lr++]);

	ll = MIN(IDENTIFIER_LEN,ll);
	lr = MIN(IDENTIFIER_LEN,lr);
	mcpy(exp->l,l,ll);
	mcpy(exp->r,r,lr);
	exp->op = op;

	return exp;
}



typedef struct _jrcp_assignment_  {
	char dst[IDENTIFIER_LEN];
	JRCPExp exp;
} * JRCPAssign;

JRCPAssign JRCPAssign_New(OE oe, const char * dst, JRCPExp exp) {
	uint ldst = 0;
	JRCPAssign assign = (JRCPAssign)oe->getmem(sizeof(*assign));
	if (!assign) {
		ERR(oe, "Out of memory");
		return 0;
	}

	while(dst[ldst++]);

	ldst = MIN(IDENTIFIER_LEN,ldst);
	mcpy(assign->dst,dst,ldst);

	assign->exp = exp;

	return assign;
}

typedef struct _joan_rene_circuit_parser_ {
	JRCPOp (*parseOp)();
	char * (*parseId)();
	JRCPAssign (*parseAssign)();
	JRCPExp (*parseExp)();
	List (*parse)();
	Data c;
	uint offset;
	OE oe;
} * JRCP;

static void eat_ws(JRCP ths) {
	uint i = ths->offset;
	while(ths->c->data[i] && isws(ths->c->data[i])) ++i;
	ths->offset = i;
}

static void eat_nl(JRCP ths) {
	if (ths->c->data[ths->offset] == '\n') ths->offset++;
}


COO_DEF(JRCP, List, parse) {
	List list = SingleLinkedList_new(this->oe);

	while(this->offset < this->c->ldata) {
		eat_ws(this);
		JRCPAssign a = this->parseAssign();
		list->add_element(a);
	}
	return list;
}}


COO_DEF(JRCP, JRCPAssign, parseAssign ){ 
	JRCPExp exp = 0;
	char * dst = 0;
	char c = 0;

	eat_ws(this);

	dst = this->parseId();
	if (!dst) return 0;

	eat_ws(this);
	c = this->c->data[this->offset++];
	if (c != '=') {
		ERR(this->oe, "Syntax error at index %u found %c expected '='.", this->offset-1,c);
		return 0;
	}

	exp = this->parseExp();
	if (!exp) return 0;

	eat_nl(this);

	return JRCPAssign_New(this->oe, dst, exp);
}}

COO_DEF(JRCP, JRCPExp, parseExp) {
	char * l = 0, * r = 0;
	JRCPOp o = JRCP_ERROR;
	eat_ws(this);

	l = this->parseId();
	if (!l) return 0;

	o = this->parseOp();
	if (o == JRCP_ERROR) return 0;

	r = this->parseId();
	if (!r) return 0;

	return JRCPExp_New(this->oe,l,o,r);
}}

COO_DEF(JRCP, char *, parseId) {
	char id[IDENTIFIER_LEN] = {0}, c=0;
	uint i = 0;
	char * res = 0;
	eat_ws(this);
	do {
		c = this->c->data[this->offset++];

		if ( (!isws(c)) && c != '\n' ) {

			if (!(c <= 'Z' && c >= '0')) {
				ERR(this->oe, "Illegal identifier at index %u",this->offset-1);
				return 0;
			}

			if (i > IDENTIFIER_LEN) {
				ERR(this->oe, "Illegal identifier length at index %u",this->offset-1);
				return 0;
			}

			id[i++] = c;
		}
	} while(!isws(c) && c != '\n');

	res = this->oe->getmem(IDENTIFIER_LEN);
	if (!res) {
		ERR(this->oe, "Out of memory");
		return 0;
	}

	mcpy(res,id,IDENTIFIER_LEN);

	return res;
}}


COO_DEF(JRCP, JRCPOp, parseOp) {
	char c = 0;
	eat_ws(this);

	c = this->c->data[this->offset];
	switch(c) {
	case '+':
		this->offset++;
		return JRCP_XOR;
	case 'x':
		this->offset++;
		return JRCP_AND;
	case '#':
		this->offset++;
		return JRCP_XNOR;
	default:
		ERR(this->oe, "Unknown operator %c at index %u",c,this->offset);
	}


	return JRCP_ERROR;
}}

JRCP JRCP_New(OE oe, Data loaded_circuit) {
	JRCP jrcp = (JRCP)oe->getmem(sizeof(*jrcp));

	if (!jrcp) return 0;

	jrcp->parseAssign = COO_attach(jrcp, JRCP_parseAssign);
	jrcp->parseExp = COO_attach(jrcp, JRCP_parseExp);
	jrcp->parseOp = COO_attach(jrcp, JRCP_parseOp);
	jrcp->parseId = COO_attach(jrcp, JRCP_parseId);
	jrcp->parse = COO_attach(jrcp, JRCP_parse);
	jrcp->c = loaded_circuit;
	jrcp->offset = 0;

	jrcp->oe = oe;

	return jrcp;
}


static void print_exp(JRCPExp exp, char * out) {
	uint n = 0;

	if (exp == 0) {
		osal_sprintf(out,"null");
		return;
	}

	n = osal_sprintf(out,"%s",exp->l);
	switch(exp->op) {
	case JRCP_XOR:
		osal_sprintf(out+n,"%c",'+');
		break;
	case JRCP_XNOR:
		osal_sprintf(out+n,"%c",'#');
		break;
	case JRCP_AND:
		osal_sprintf(out+n,"%c",'*');
		break;
	default:
		osal_sprintf(out+n,"?");
	}
	++n;
	osal_sprintf(out+n,"%s",exp->r);
}

static void print_ast(OE oe, List ast) {

	JRCPAssign cur = 0;
	uint i = 0;
	const uint s = ast->size();
	for ( i = 0; i < s;++i) {
		cur = ast->get_element(i);
		if (cur) {
			char buf[64] = {0};
			print_exp(cur->exp,buf);
			oe->print("%s=%s\n",cur->dst,buf);
		} else {
			oe->print("Error: null node in AST.\n");
		}
	}

}

static void print_exp_mmcomp(Map heap, uint * id_pool_ptr, uint dst_addr, JRCPExp exp, char * out) {
	uint n = 0;
	uint left_addr = 0;
	uint right_addr = 0;
	uint id_pool = *id_pool_ptr;

	if (exp == 0) {
		osal_sprintf(out,"null");
		return;
	}

	if (heap->contains(exp->l)) {
		left_addr = (uint)(ull)heap->get(exp->l);
	} else {
		left_addr = id_pool++;
		heap->put(exp->l,(void*)(ull)left_addr);
	}

	if (heap->contains(exp->r)) {
		right_addr = (uint)(ull)heap->get(exp->r);
	} else {
		right_addr = id_pool++;
		heap->put(exp->l,(void*)(ull)right_addr);
	}


	switch(exp->op) {
	case JRCP_XOR:
		n = osal_sprintf(out,"mm->xor(%u,%u,%u);\n",dst_addr,left_addr,right_addr);
		break;
	case JRCP_XNOR:{
		uint tmp_addr = id_pool++;
		n = osal_sprintf(out,"mm->xor(%u,ONE,%u);\nmm->xor(%u,%u,%u);\n",dst_addr,tmp_addr,tmp_addr,left_addr,right_addr);
	}
		break;
	case JRCP_AND:
		n = osal_sprintf(out,"mm->and(%u,%u,%u)\n",dst_addr,left_addr,right_addr);
		break;
	default:
		osal_sprintf(out+n,"?");
	}
	++n;
	osal_sprintf(out+n,"%s",exp->r);
	*id_pool_ptr = id_pool;
}

Map HashMap_StrKey_New(OE oe, uint buckets);
static void print_ast_mmcomp(OE oe, uint pool_offset,List ast) {
	uint id_pool=pool_offset;
	Map heap = HashMap_StrKey_New(oe,16);
	JRCPAssign cur = 0;
	uint i = 0;
	const uint s = ast->size();
	uint dst_addr = 0;



	for ( i = 0; i < s;++i) {
		cur = ast->get_element(i);
		if (cur) {
			char buf[64] = {0};

			if (heap->contains(cur->dst)) {
				dst_addr = (uint)(ull)heap->get(cur->dst);
			} else {
				dst_addr = id_pool++;
				heap->put(cur->dst,(void*)(ull)dst_addr);
			}


			print_exp_mmcomp(heap,&id_pool,dst_addr,cur->exp,buf);
			oe->print("%s",buf);
		} else {
			oe->print("Error: null node in AST.\n");
		}
	}

}

RC compile_circuit(OE oe, const char * filename, uint offset) {
	RC rc = RC_OK;
	uint lfilename = 0;
	FD fd = 0;
	byte * openreq = 0;
	byte * buffer = 0;
	uint lbuffer = 1024*1024;
	JRCP parser = 0;

	buffer = oe->getmem(lbuffer);
	if (!buffer) {
		ERR(oe,"Out of memory.");
		return RC_NOMEM;
	}

	while(filename[lfilename++] != 0);

	openreq = oe->getmem(lfilename+8);
	if (!openreq) return RC_NOMEM;

	osal_sprintf(openreq,"file %s",filename);
	rc = oe->open(openreq, &fd);
	if (rc != RC_OK) goto fail;

	rc = oe->read(fd,buffer, &lbuffer);
	if (rc != RC_OK) {
		ERR(oe,"Failed to read file");
		return rc;
	}

	oe->close(fd);
	parser = JRCP_New(oe,Data_shallow(buffer,lbuffer));
	if (!parser) {
		ERR(oe, "No Memory");
		return RC_NOMEM;
	}

	{
		List ast = parser->parse();
		oe->print("Got AST of size %u.\n", ast->size());
		print_ast_mmcomp(oe,offset,ast);
	}


	return RC_OK;
	fail:
	oe->putmem(openreq);
	return rc;
}

