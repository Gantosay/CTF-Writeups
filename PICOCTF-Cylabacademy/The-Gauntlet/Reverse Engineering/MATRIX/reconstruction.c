#include <stdio.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* VM context: one instance drives one program's execution.            */
/* ------------------------------------------------------------------ */
typedef struct {
    const unsigned char *bytecode;   /* fixed base pointer into .rodata */
    unsigned short ip;               /* instruction pointer             */
    unsigned short *data_stack;      /* 0x800-byte malloc'd buffer       */
    unsigned short *aux_stack;       /* 0x800-byte malloc'd buffer       */
    int  (*read_char)(void);         /* getc(stdin) wrapper              */
    void (*write_char)(int);         /* putc(stdout) wrapper             */
} vm_context_t;

typedef struct {
    unsigned char  error_flag;   /* set nonzero only on a genuine VM fault */
    unsigned short exit_code;    /* value popped by HALT                   */
} vm_result_t;

/* ------------------------------------------------------------------ */
/* One VM instruction. Returns 1 while still running, 0 once halted.    */
/* ------------------------------------------------------------------ */
int vm_step(vm_context_t *ctx, vm_result_t *result) {
    unsigned char opcode = ctx->bytecode[ctx->ip];
    ctx->ip += 1;

    switch (opcode) {
        case 0x00: /* NOP   */ return 1;

        case 0x01: { /* HALT */
            unsigned short code = *--ctx->data_stack_top_ptr_equivalent; /* pop */
            if (result) {
                result->error_flag = 0;
                result->exit_code  = code;
            }
            return 0;
        }

        case 0x10: /* DUP    */ push(ctx, peek(ctx));                         return 1;
        case 0x11: /* POP    */ pop(ctx);                                     return 1;
        case 0x12: /* ADD    */ { unsigned short b = pop(ctx), a = pop(ctx); push(ctx, a + b); } return 1;
        case 0x13: /* SUB    */ { unsigned short b = pop(ctx), a = pop(ctx); push(ctx, a - b); } return 1;
        case 0x14: /* SWAP   */ swap_top_two(ctx);                            return 1;

        case 0x20: /* PUSH_R */ push_aux(ctx, pop(ctx));                      return 1;
        case 0x21: /* POP_R  */ push(ctx, pop_aux(ctx));                      return 1;

        case 0x30: /* JMP    */ ctx->ip = pop(ctx);                           return 1;
        case 0x31: /* JZ     */ { unsigned short addr = pop(ctx), val = pop(ctx); if (val == 0)           ctx->ip = addr; } return 1;
        case 0x32: /* JNZ    */ { unsigned short addr = pop(ctx), val = pop(ctx); if (val != 0)           ctx->ip = addr; } return 1;
        case 0x33: /* JS     */ { unsigned short addr = pop(ctx); short val = (short)pop(ctx); if (val < 0)  ctx->ip = addr; } return 1;
        case 0x34: /* JLE    */ { unsigned short addr = pop(ctx); short val = (short)pop(ctx); if (val <= 0) ctx->ip = addr; } return 1;

        case 0x80: { /* PUSH8  */
            signed char imm = (signed char)ctx->bytecode[ctx->ip];
            ctx->ip += 1;
            push(ctx, (short)imm);
            return 1;
        }
        case 0x81: { /* PUSH16 */
            unsigned short imm = ctx->bytecode[ctx->ip] | (ctx->bytecode[ctx->ip + 1] << 8);
            ctx->ip += 2;
            push(ctx, imm);
            return 1;
        }

        case 0xc0: /* GETC   */ push(ctx, (unsigned char)ctx->read_char());   return 1;
        case 0xc1: /* PUTC   */ ctx->write_char((unsigned char)pop(ctx));     return 1;

        default:
            if (result) result->error_flag = 1;
            return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Host program                                                         */
/* ------------------------------------------------------------------ */
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0x2000);

    vm_context_t ctx = {
        .bytecode   = MAZE_BYTECODE,     /* the 0x20f0-based blob, including the 16x16 table */
        .ip         = 0,
        .data_stack = malloc(0x800),
        .aux_stack  = malloc(0x800),
        .read_char  = getc_wrapper,
        .write_char = putc_wrapper,
    };

    vm_result_t result = {0};

    while (vm_step(&ctx, &result)) {
        /* loop until HALT or fault */
    }

    free(ctx.data_stack);
    free(ctx.aux_stack);

    if (result.error_flag == 0 && result.exit_code == 0) {
        puts("Have a flag!");
        FILE *f = fopen("flag.txt", "r");
        char buf[0x100];
        fgets(buf, sizeof(buf), f);
        fclose(f);
        puts(buf);
    }

    return 0;
}