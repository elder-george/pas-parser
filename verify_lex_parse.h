#pragma once

typedef struct PrintVisitor PrintVisitor;
struct PrintVisitor{
    Visitor v;
    FILE *fout;
};
#define FOUT(vis) FILE *fout = ((PrintVisitor*)vis)->fout
static void print_program(Visitor *vis, Program *program) {
    FOUT(vis);
    fprintf(fout, "PROGRAM\n");
    if (vis->visit_Proc) {
        for (size_t i = 0; i < program->procs.size; ++i){
            Proc *proc = vec_Proc_at(&program->procs, i);
            vis->visit_Proc(vis, proc);
        }
    }
    fprintf(fout, "/PROGRAM\n");
}

static void print_proc(Visitor *vis, Proc *proc) {
    FOUT(vis);
    fprintf(fout, "PROC %s\n", proc->name);
    if (vis->visit_Arg) {
        for (size_t i = 0; i < proc->args.size; ++i){
            vis->visit_Arg(vis, vec_Arg_at(&proc->args, i));
        }
    }
    if (vis->visit_Stmt) {
        fprintf(fout, "BLOCK\n");
        for (size_t i = 0; i < proc->block.size; ++i) {
            vis->visit_Stmt(vis, vec_Stmt_at(&proc->block, i));
        }
        fprintf(fout, "/BLOCK\n");
    }
    fprintf(fout, "/PROC\n");
}

static void print_arg(Visitor *vis, Arg *arg) {
    FOUT(vis);
    fprintf(fout, "ARG %s %s\n", arg->name, arg->type);
}

static void print_stmt(Visitor *vis, Stmt *stmt){
    FOUT(vis);
    switch(stmt->type){
    case stmtAssign:
        if(vis->visit_Assignment) vis->visit_Assignment(vis, &stmt->assign);
        break;
    case stmtForLoop:
        if(vis->visit_ForLoop) vis->visit_ForLoop(vis, &stmt->forLoop);
        break;
    case stmtCond:
        if(vis->visit_Conditional) vis->visit_Conditional(vis, &stmt->cond);
        break;
    case stmtCall:
        if (vis->visit_Call) vis->visit_Call(vis, &stmt->call);
        break;
    default:
        assert(!"Unexpected stmt type");
    }
}

void print_assignment(Visitor* vis, Assignment *assign){
    FOUT(vis);
    fprintf(fout, "ASSIGN %s\n", assign->lvalue);
    if(vis->visit_Expr) vis->visit_Expr(vis, &assign->expr);
    fprintf(fout, "/ASSIGN\n");
}

void print_forloop(Visitor* vis, ForLoop* forLoop){
    FOUT(vis);
    fprintf(fout, "FOR %s\n", forLoop->var);
    if(vis->visit_Expr) vis->visit_Expr(vis, &forLoop->left);
    if(vis->visit_Expr) vis->visit_Expr(vis, &forLoop->right);
    fprintf(fout, "BLOCK\n");
    if (vis->visit_Stmt) {
        for (size_t i = 0; i < forLoop->block.size; ++i) {
            if(vis->visit_Stmt) vis->visit_Stmt(vis, vec_Stmt_at(&forLoop->block, i));
        }                                            
    }
    fprintf(fout, "/BLOCK\n");
    fprintf(fout, "/FOR\n");
}

void print_cond(Visitor *vis, Conditional *cond) {
    FOUT(vis);
    fprintf(fout, "IF\n");
    if (vis->visit_Expr) vis->visit_Expr(vis, &cond->cond);
    fprintf(fout, "THEN\n");
    if (vis->visit_Stmt) {
        for (size_t i = 0; i < cond->onThen.size; ++i) {
            if(vis->visit_Stmt) vis->visit_Stmt(vis, vec_Stmt_at(&cond->onThen, i));
        }
    }
    fprintf(fout, "/THEN\n");
    if (cond->onElse.size > 0){
        fprintf(fout, "ELSE\n");
        for (size_t i = 0; i < cond->onElse.size; ++i) {
            if(vis->visit_Stmt) vis->visit_Stmt(vis, vec_Stmt_at(&cond->onElse, i));
        }
        fprintf(fout, "/ELSE\n");
    }
}

void print_call(Visitor *vis, Call *call){
    FOUT(vis);
    fprintf(fout, "CALL %s\n", call->procName);
    if (vis->visit_Expr){
        for (size_t i = 0; i < call->params.size; ++i){
            vis->visit_Expr(vis, vec_Expr_at(&call->params, i));
        }
    }
    fprintf(fout, "/CALL\n");
}

void print_expr(Visitor *vis, Expr *expr){
    FOUT(vis);
    switch(expr->type){
    case exprNumValue:
        fprintf(fout, "NUM %d\n", expr->num);
        break;
    case exprStrValue:
        fprintf(fout, "STR \"%s\"\n", expr->str);
        break;
    case exprVar:
        fprintf(fout, "VAR %s\n", expr->str);
        break;
    case exprBinary:
        fprintf(fout, "OP %s\n", Operator_Names[expr->op]);
        vis->visit_Expr(vis, expr->lhs);
        vis->visit_Expr(vis, expr->rhs);
        fprintf(fout, "/OP %s\n", Operator_Names[expr->op]);
        break;
    case exprCall:
        vis->visit_Call(vis, &expr->call);
        break;
    }
}
#undef FOUT


#define DIFF_TOOL "busybox diff"

void diff_files(const char *a, const char *b){
    char cmd_line[256];
    snprintf(cmd_line, 255, "%s %s %s", DIFF_TOOL, a, b);
    assert(0 == system(cmd_line));
}

char* read_all_text(const char *path){
    FILE *f = fopen(path, "rb");
    assert(f && "Can't read source file");
    fseek(f, 0, SEEK_END);
    int size = ftell(f);
    char *text = calloc(1, size + 1);
    assert(text && "Can't allocate enough memory");
    rewind(f);
    int read_bytes = fread(text, size, 1, f);
    fclose(f);
    return text;
}

char *mk_output_name(const char* expected_name){
     char output_name[256];
     snprintf(output_name, 255, "actual.%s", expected_name);
     return strdup(output_name);    
}

FILE* open_output_file(const char* output_name){
     FILE *fout = fopen(output_name, "w");
     return fout;
}

void verify_lex_parse(const char *src, const char *lex, const char *parse){
    printf("%s\n", __FUNCTION__);
    char *src_text = read_all_text(src);

    if (lex){
        char *lex_out = mk_output_name(lex);
        FILE* f_lex = open_output_file(lex_out);
        assert(f_lex && "Can't open file for lexer output");
        print_tokens(f_lex, src_text);
        fclose(f_lex);
        diff_files(lex, lex_out);
        free(lex_out);
    }

    if (parse){
        Lexer lexer;
        init_lexer(&lexer, src_text);
        Program program = { {sizeof(Proc)} };
        assert(build_program_ast(&lexer, &program) && "Failed to parse program");

        char *parse_out = mk_output_name(parse);
        FILE *f_parse = open_output_file(parse_out);
        assert(f_parse && "Can't open file for parser output");
        PrintVisitor vis = {
            {
                .visit_Program = print_program, 
                .visit_Proc = print_proc,
                .visit_Arg = print_arg,
                .visit_Stmt = print_stmt,
                .visit_ForLoop = print_forloop,
                .visit_Assignment = print_assignment,
                .visit_Call = print_call,
                .visit_Conditional = print_cond,
                .visit_Expr = print_expr,
            },
            f_parse
        };
        vis.v.visit_Program(&vis.v, &program);
        fclose(f_parse);
        diff_files(parse, parse_out);
        free(parse_out);
        Program_free(&program);
        free(src_text);
    }
}

void verify_expr(const char *src, const char *parse){
    printf("%s\n", __FUNCTION__);
    char *src_text = read_all_text(src);
    Lexer lexer;
    init_lexer(&lexer, src_text);

    Expr expr;
    assert(build_expr_ast(&lexer, &expr) && "Failed to parse expression");
    char *parse_out = mk_output_name(parse);
    FILE *f_parse = open_output_file(parse_out);
    assert(f_parse && "Can't open file for parser output");
    PrintVisitor vis = {
        {
            .visit_Expr = print_expr,
            .visit_Call = print_call,
        },
        f_parse
    };
    vis.v.visit_Expr(&vis.v, &expr);
    fclose(f_parse);
    diff_files(parse, parse_out);
    free(parse_out);
    Expr_free(&expr);
    free(src_text);
}
