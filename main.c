#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <io.h>

#define ENUM_VAL(_, V, ...) V,
#define ENUM_NAME(N, _, ...) N,

#define DEF_ENUM(NAME, VALUE_LIST)\
typedef enum NAME NAME;\
enum NAME {\
    VALUE_LIST(ENUM_VAL)\
    NAME##_Count,\
};\
\
const char* const NAME##_Names[NAME##_Count] = {\
    VALUE_LIST(ENUM_NAME)\
}

#define TOKEN_TYPES(val)\
    val("Comment",      ttComment,    "{%255[^}]}%n")\
    val("NL",           ttNewline,    "%255[\r\n]%n")\
    val("WS",           ttWhitespace, "%255[ \t\n\r]%n")\
    val("Ident",        ttIdent,      "%255[a-zA-Z_]%n")\
    val("Keyword",      ttKw,         NULL)\
    val("Number",       ttNumberLit,  "%255[0-9]%n")\
    val("String",       ttStringLit,  "\"%255[^\"]\"%n")\
    val("Operator/Delim", ttOperatorOrDelim, "%255[-+*/=<>:,;]%n")\
    val("Operator",     ttOper,       NULL)\
    val("Delim",        ttDelim,      NULL)\
    val("Bracket",      ttBracket,    "%1[][()]%n")

DEF_ENUM(TokenTypes, TOKEN_TYPES);

#define TOKEN_PATTERN(N, V, P) P,
const char * const TokenPatterns[TokenTypes_Count] = {
    TOKEN_TYPES(TOKEN_PATTERN)
};

#define KEYWORDS(val)\
    val("proc", kwProc)\
    val("begin",kwBegin)\
    val("end", kwEnd)\
    val("for", kwFor)\
    val("to", kwTo)\
    val("do", kwDo)\
    val("if", kwIf)\
    val("then", kwThen)\
    val("else", kwElse)

DEF_ENUM(Keyword, KEYWORDS);

#define OPERATORS(val)\
    val(":=", OpAssign, -1)\
    val("=",  OpEqual,   0)\
    val("-",  OpMinus,   1)\
    val("+",  OpPlus,    1)\
    val("/",  OpDiv,     2)\
    val("%",  OpMod,     2)\
    val("*",  OpMul,     2)

DEF_ENUM(Operator, OPERATORS);
#define OP_PRECEDENCE(_, __, P) P,
const int OpPrecedence[Operator_Count] = {
    OPERATORS(OP_PRECEDENCE)
};

#define DELIMS(val)\
    val(",", Comma)\
    val(":", Colon)\
    val(";", Semicolon)

DEF_ENUM(Delimiter, DELIMS);

#define BRACKETS(val)\
    val("(", LeftPar)\
    val(")", RightPar)\
    val("[", RightBrace)\
    val("]", RightBrace)

DEF_ENUM(Bracket, BRACKETS);

typedef struct Token Token;
struct Token {
    TokenTypes type;
    size_t line_no;
    size_t col;
    union {
        char *str;
        Keyword kw;
        Operator op;
        Bracket br;
        Delimiter delim;
        int num;
    };
};
void TokenToString(const Token *token, int buf_size, char *buf){
    switch(token->type){
        case ttNumberLit:
            snprintf(buf, buf_size, "%d", token->num);
            break;
        case ttWhitespace:
            *buf = ' ';
            break;
        case ttNewline:
            strncpy(buf, "\\n", buf_size);
            break;
        case ttOper:
            strncpy(buf, Operator_Names[token->op], buf_size);
            break;
        case ttDelim:
            strncpy(buf, Delimiter_Names[token->delim], buf_size);
            break;
        case ttKw:
            strncpy(buf, Keyword_Names[token->kw], buf_size);
            break;
        case ttBracket:
            strncpy(buf, Bracket_Names[token->br], buf_size);
            break;
        case ttIdent:
        case ttStringLit:
        case ttComment:
            strncpy(buf, token->str, buf_size);
            break;
    }

}

void Token_free(Token* token){
    switch(token->type){
        case ttIdent:
        case ttStringLit:
        case ttComment:
            free(token->str);
            token->str = NULL;
    }
}

typedef struct Lexer Lexer;
struct Lexer{
    char *input;
    size_t line_no, col;
    Token lookahead;
};

void init_lexer(Lexer *lexer, char* input){
    lexer->input = input;
    lexer->line_no = 1;
    lexer->col = 1;
    lexer->lookahead = (Token){ .type = TokenTypes_Count, 0, 0, 0}; // invalid value;
}

int match_one_of(int count, const char* const values[], char* val){
    for (int i = 0; i < count; ++i){
        if (0 == strcmp(val, values[i])){
            return i;
        }
    }
    return count;
}

bool build_token(Token *token, TokenTypes type, char token_text[], size_t line_no, size_t col) {
    token->type = type;
    token->line_no = line_no;
    token->col = col;
    switch(token->type) {
        case ttNumberLit:
            token->num = atoi(token_text);
            break;
        case ttStringLit:
        case ttComment:
            token->str = strdup(token_text);
            break;
        case ttIdent: {
            // "Upgrade" identifiers to keywords
            Keyword kw = match_one_of(Keyword_Count, Keyword_Names, token_text);
            if (kw != Keyword_Count){
                token->type = ttKw;
                token->kw = kw;
            } else {
                token->str = strdup(token_text);
            }
            break;
        }
        case ttOperatorOrDelim: {
            Operator op;
            Delimiter delim;
            if ((op = match_one_of(Operator_Count, Operator_Names, token_text)) != Operator_Count) {
                token->type = ttOper;
                token->op = op;
            } else if ((delim = match_one_of(Delimiter_Count, Delimiter_Names, token_text)) != Delimiter_Count) {
                token->type = ttDelim;
                token->delim = delim;
            } else {
                fprintf(stderr, "Invalid operator or delimiter %s (%d:%d)\n", token_text, token->line_no, token->col);
                return false;
            }
            break;
        }
        case ttBracket: 
            token->br = match_one_of(Bracket_Count, Bracket_Names, token_text);
            break;
        default:
            token->str = NULL;
    }
    return true;
}

bool get_token_no_filter(Lexer *lexer, Token *token){
    if (lexer->lookahead.type != TokenTypes_Count){
        *token = lexer->lookahead;
        lexer->lookahead = (Token){ TokenTypes_Count, 0};
        return true;
    }
    assert(lexer->input);
    if (!*lexer->input) return false;
    char w[256] = {0};
    size_t len;
    TokenTypes tk = 0;

    for (; tk < TokenTypes_Count; ++tk){
        if (!TokenPatterns[tk]) continue;
        int read_token = sscanf(lexer->input, TokenPatterns[tk], w, &len);
        if (read_token) {
            if (!build_token(token, tk, w, lexer->line_no, lexer->col)) {
                return false;
            }
            lexer->input += len;
            lexer->col += len;
            if (tk == ttNewline){
                lexer->line_no++;
                lexer->col = 1;
            }
            break;
        }
    }
    if (tk == TokenTypes_Count){
        fprintf(stderr, "Couldn't match %s (%d:%d) with any pattern\n", lexer->input, lexer->line_no, lexer->col);
        return false;                                       
    }
    return true;
}

bool get_token(Lexer *lexer, Token *token) {
    do{
        if(!get_token_no_filter(lexer, token)){
            return false;
        }
    } while(token->type == ttWhitespace 
        || token->type == ttNewline 
        || token->type == ttComment);
    return true;
}

void unget_token(Lexer *lexer, Token *token){
    lexer->lookahead = *token;
    token->type = TokenTypes_Count;
}

static void print_tokens(FILE* fout, char *input){
    Lexer lexer;
    init_lexer(&lexer, input);
    Token token;
    while(get_token(&lexer, &token)){
        char buf[256] = {0};
        TokenToString(&token, sizeof(buf) / sizeof(buf[0]), buf);

        fprintf(fout, "%s <%s> at %d:%d\n", 
            TokenTypes_Names[token.type],
            buf,
            token.line_no, 
            token.col);

        Token_free(&token);
    }
}

typedef struct vec vec;
struct vec {
    size_t item_size, cap, size;
    void *data;
};

void vec_alloc(vec *v, size_t item_size, size_t cap){
    v->data = calloc(cap, item_size);
    assert(v->data && "Failed to alloc");
    v->item_size = item_size;
    v->cap = cap;
    v->size = 0;
}

void vec_free(vec * v){
    free(v->data);
    v->data = NULL;
    v->cap = 0;
    v->size = 0;
}

void vec_push(vec *v, void *addr){
    assert(v->item_size);
    if (!v->data){
        vec_alloc(v, v->item_size, 2);
    } else if (v->size >= v->cap) {
        size_t new_cap = v->cap * 2;
        void *new_data = realloc(v->data, v->item_size * new_cap);
        assert(new_data && "Failed to increase capacity");
        v->data = new_data;
        v->cap = new_cap;
    }
    memcpy(v->data+v->size*v->item_size, addr, v->item_size);
    v->size++;
}

#define DEF_VECTOR_OF(TYPE)\
    void vec_##TYPE##_push(vec *v, TYPE val) {\
        assert(v->item_size == sizeof(TYPE));\
        vec_push(v, &val);\
    }\
    TYPE *vec_##TYPE##_at(vec *v, size_t i){\
        assert(i < v->size);\
        assert(v->item_size == sizeof(TYPE));\
        return ((TYPE*)v->data) + i;\
    }
#define vec_foreach(VEC, TYPE, VAR, BLOCK)\
    for (size_t i = 0; i < VEC.size; ++i) {\
        TYPE *VAR = vec_##TYPE##_at(&VEC, i);\
        BLOCK\
    }

/*
Program -> Proc (';' Proc)* .
Proc -> 'proc' Ident '(' Arg_list ')' Block .
    Arg_list -> () | Arg (';' Arg)* .
        Arg -> Ident ':' Ident .    // ignoring complex types for now
    Block -> 'begin' Statements 'end'
    Statements -> Statement (';' Statement)* .
        Statement -> Assignment | Call | Conditional | ForLoop .
            Assignment -> LValue ':=' Expr .
                LValue -> Ident .   // Ignoring arrays for now
                Expr -> Term | Expr ('+'|'-') Term .
                    Term -> Factor | Term ('*'|'/') Factor .
                        Factor -> Number | Ident | '(' Expr ')' .
            Call -> Ident '(' Param_List ')'
                Param_List -> Expr (',' Expr)* .
            Conditional -> 'if' Expr 'then' Block ('else' Block) .
            ForLoop -> 'for' Ident ':=' Expr 'to' Expr 'do' Block .
*/

#define AST_NODES(val)\
    val("Program", astProgram)\
    val("Proc", astProc)\
    val("Arg", astArg)\
    val("Stmt", astStmt)\
    val("Assign", astAssign)\
    val("Expr", astExpr)\
    val("Call", astCall)\
    val("Cond", astCond)\
    val("For", astFor)

DEF_ENUM(AstNode, AST_NODES);

#define FWD_STRUCT(NAME) typedef struct NAME NAME
FWD_STRUCT(Program);
FWD_STRUCT(Proc);
FWD_STRUCT(Arg);
FWD_STRUCT(Stmt);
FWD_STRUCT(Assignment);
FWD_STRUCT(Expr);
FWD_STRUCT(Call);
FWD_STRUCT(Conditional);
FWD_STRUCT(ForLoop);

// had to define `Call` first, otherwise cross-dependency don't work;
// even here, it works mostly because of type-erasing vector.
struct Call{
    char *procName;
    vec params;
};

struct Expr{
    enum {
        exprNumValue,
        exprStrValue,
        exprVar,
        exprCall,
        exprBinary,
    } type; 
    union{
        int num;
        char *str;
        Call call;
        struct {
            Operator op;
            Expr *lhs;
            Expr *rhs;
        };
    };
};
DEF_VECTOR_OF(Expr);

struct Arg{
    char *name;
    char *type;
};
DEF_VECTOR_OF(Arg);
void Arg_free(Arg *arg) {
    free(arg->name);
    free(arg->type);
}

struct Proc{
    char *name;
    vec args;
    vec block;
};
DEF_VECTOR_OF(Proc);

struct Program{
    vec procs;
};

struct Assignment{
    char *lvalue;
    Expr expr;
};

struct Conditional{
    Expr cond;
    vec onThen, onElse;
};

struct ForLoop{
    char *var;
    Expr left, right;
    vec block;
};

struct Stmt{
    enum{
        stmtAssign,
        stmtCall,
        stmtCond,
        stmtForLoop
    } type;
    union{
        Assignment assign;
        Call call;
        Conditional cond;
        ForLoop forLoop;
    };
};
DEF_VECTOR_OF(Stmt);

void Expr_free(Expr *expr);

void Call_free(Call *call){
    free(call->procName);
    call->procName = NULL;
    vec_foreach(call->params, Expr, param, {
        Expr_free(param);
    });
    vec_free(&call->params);
}

void Expr_free(Expr *expr) {
    switch(expr->type){
    case exprNumValue:
        // Nothing to do
        break;
    case exprStrValue:
    case exprVar:
        free(expr->str);
        expr->str = NULL;
        break;
    case exprCall:
        Call_free(&expr->call);
        break;
    case exprBinary:
        Expr_free(expr->lhs);
        expr->lhs = NULL;
        Expr_free(expr->rhs);
        expr->rhs = NULL;
        break;
    }
}

void Stmt_free(Stmt *stmt){
    switch(stmt->type){
    case stmtAssign: {
            Assignment *assign = &stmt->assign;
            free(assign->lvalue);
            assign->lvalue = NULL;
            free(&assign->expr);
            break;
        }
    case stmtCall: {
        Call *call = &stmt->call;
        Call_free(call);
        break;
    }
    case stmtCond: {
        Conditional *cond = &stmt->cond;
        Expr_free(&cond->cond);
        vec_foreach(cond->onThen, Stmt, stmt, {
            Stmt_free(stmt);
        });
        vec_free(&cond->onThen);
        vec_foreach(cond->onElse, Stmt, stmt, {
            Stmt_free(stmt);
        });
        vec_free(&cond->onElse);
    }
    }
}

void Proc_free(Proc *proc){
    free(proc->name);
    vec_foreach(proc->args, Arg, arg, {
        Arg_free(arg);
    });
    vec_free(&proc->args);
    vec_foreach(proc->block, Stmt, stmt, {
        Stmt_free(stmt);
    });
    vec_free(&proc->block);
}

void Program_free(Program *program){
    vec_foreach(program->procs, Proc, proc, {
        Proc_free(proc);
    });
    vec_free(&program->procs);
}



bool build_proc_ast(Lexer *lexer, Proc *proc);

static const char BadTokenFmt[] = "Expected %s but got %s\n";

#define LOG_TOKEN(FMT, TOKEN) do {\
     char buf[256];\
     TokenToString(&TOKEN, sizeof(buf)/sizeof(buf[0]), buf);\
     fprintf(stderr, FMT, buf);\
}while (false)

#define BAD_TOKEN(EXPECTED, TOKEN) do{\
     char buf[256];\
     TokenToString(&TOKEN, sizeof(buf)/sizeof(buf[0]), buf);\
     fprintf(stderr, BadTokenFmt, EXPECTED, buf);\
} while(false)

bool build_program_ast(Lexer *lexer, Program *program){
    for(Token token; get_token(lexer, &token);){
        if (!(token.type == ttKw && token.kw == kwProc)){
            BAD_TOKEN("'proc'", token);
            return false;
        }
        Proc proc = { NULL, {sizeof(Arg)}, {sizeof(Stmt)} };
        if (!build_proc_ast(lexer, &proc)){
            return false;
        }
        vec_Proc_push(&program->procs, proc);
    }
    return true;
}

bool build_args_ast(Lexer* lexer, vec *args);
bool build_block_ast(Lexer* lexer, vec *stmts);
bool build_proc_ast(Lexer *lexer, Proc *proc){
    Token token;
    if (!get_token(lexer, &token)) return false;
    if (token.type != ttIdent){
       BAD_TOKEN("identifier", token);
       return false;
    }
    proc->name = token.str;
    token.str = NULL;

    if (!get_token(lexer, &token)) return false;
    if (!(token.type == ttBracket && token.br == LeftPar)){
        BAD_TOKEN("'('", token);
        return false;
    }
    if (!build_args_ast(lexer, &proc->args)) {
        fprintf(stderr, "Invalid argument list\n");
        return false;
    }
    if (!build_block_ast(lexer, &proc->block)){
        fprintf(stderr, "Invalid procedure body\n");
        return false;
    }
    return true;
}

bool build_args_ast(Lexer* lexer, vec *args) {
    Token token;
    enum {
        DEFAULT,
        ACCEPT_NAME,
        HAVE_NAME,
        HAVE_COLON,
        ACCEPT_COMMA
    } state = DEFAULT;
    Arg arg = {0};
    while(true){
        if (!get_token(lexer, &token)) return false;
        switch(state) {
        case DEFAULT:
            if(token.type == ttBracket && token.br == RightPar) {
                return true;
            }
            // FALLTHROUGH
        case ACCEPT_NAME:
            if (token.type != ttIdent) {
                BAD_TOKEN("argument name", token);
                return false;
            }
            arg.name = token.str;
            token.str = NULL;
            state = HAVE_NAME;
            break;
        case HAVE_NAME:
            if (!(token.type == ttDelim && token.delim == Colon)) {
                BAD_TOKEN("':'", token);
                return false;
            }
            state = HAVE_COLON;
            break;
        case HAVE_COLON:
            if (token.type != ttIdent) {
                BAD_TOKEN("type name", token);
                return false;
            }
            arg.type = token.str;
            token.str = NULL;
            vec_Arg_push(args, arg);
            arg = (Arg){0};
            state = ACCEPT_COMMA;
            break;
        case ACCEPT_COMMA:
            if(token.type == ttBracket && token.br == RightPar) {
                return true;
            }
            if (!(token.type == ttDelim && token.delim == Comma)) {
                BAD_TOKEN("','", token);
                return false;                
            }
            state = ACCEPT_NAME;
            break;
        }
    }
    return false;
}

bool build_stmt_ast(Lexer *lexer, Stmt *stmt);
bool build_block_ast(Lexer *lexer, vec *stmts){
    assert(!stmts->data && !stmts->size && !stmts->cap);
    enum {
        WAIT_BEGIN,
        WAIT_STMT_OR_END,
        WAIT_STMT,
        WAIT_DELIM_OR_END
    } state = WAIT_BEGIN;
    while(true){
        Token token  = {0};
        if (!get_token(lexer, &token)){
            return false;
        }
        switch(state){
        case WAIT_BEGIN:
            if (token.type != ttKw && token.kw != kwBegin){
                BAD_TOKEN("'begin'", token);
                return false;
            }
            state = WAIT_STMT_OR_END;
            break;
        case WAIT_STMT_OR_END:
            if (token.type == ttKw && token.kw == kwEnd) {
                return true;
            }
            // FALLTHROUGH
        case WAIT_STMT: {
                unget_token(lexer, &token);
                Stmt stmt = {0, {0,}};
                if (!build_stmt_ast(lexer, &stmt)){
                    fprintf(stderr, "Invalid statement\n");
                    return false;
                }
                vec_Stmt_push(stmts, stmt);
                state = WAIT_DELIM_OR_END;
                break;
            }
        case WAIT_DELIM_OR_END:
            if(token.type == ttKw && token.kw == kwEnd) {
                return true;
            }
            if (!(token.type == ttDelim && token.delim == Semicolon)){
                BAD_TOKEN("';'", token);
                return false;
            }
            state = WAIT_STMT;
            break;
        }
    };
    return false;
}

bool build_for_loop_ast(Lexer *lexer, ForLoop *forLoop);
bool build_cond_ast(Lexer *lexer, Conditional *cond);
bool build_expr_ast(Lexer *lexer, Expr *cond);
bool build_param_list_ast(Lexer *lexer, vec* params);

bool build_stmt_ast(Lexer *lexer, Stmt *stmt){
    Token token;
    if (!get_token(lexer, &token)){
        return false;
    }
    if (token.type == ttKw){
        switch(token.kw){
        case kwFor: {
            ForLoop forLoop = {0,0,0};
            if (!build_for_loop_ast(lexer, &forLoop)){
                return false;
            }
            stmt->type = stmtForLoop;
            stmt->forLoop = forLoop;
            assert(forLoop.var);
            assert(stmt->forLoop.var);
            return true;
        }
        case kwIf: {
            Conditional cond = {0};
            if (!build_cond_ast(lexer, &cond)){
                return false;
            }
            stmt->type = stmtCond;
            stmt->cond = cond;
            return true;
        }
        }
    } else if (token.type == ttIdent) {
        char *ident = token.str; token.str = NULL;
        if (!get_token(lexer, &token))
            return false;
        if (token.type == ttOper && token.op == OpAssign){
            Assignment assign = { .lvalue = ident, {0}};
            if (!build_expr_ast(lexer, &assign.expr)) return false;
            stmt->type = stmtAssign;
            stmt->assign = assign;
            return true;
        } else if (token.type == ttBracket && token.br == LeftPar){
            Call call = { .procName = ident, {sizeof(Expr)} };
            if (!build_param_list_ast(lexer, &call.params)){
                fprintf(stderr, "Invalid parameter list\n");
                return false;
            }
            stmt->type = stmtCall;
            stmt->call = call;
            return true;
        } 
    }
    BAD_TOKEN("loop, conditional, call or assignment", token);
    return false;
}

bool build_for_loop_ast(Lexer *lexer, ForLoop *forLoop){
    Token token;
    if (!get_token(lexer, &token)) return false;
    if (token.type != ttIdent) { 
        BAD_TOKEN("variable name", token);
        return false;
    }
    char *var = token.str;
    //token.str = NULL;
    if (!get_token(lexer, &token)) return false;
    if (token.type != ttOper && token.op != OpAssign) {
        BAD_TOKEN("':='", token);
        return false;
    }
    Expr left = {0};
    if (!build_expr_ast(lexer, &left)) return false;
    if (!get_token(lexer, &token)) return false;
    if (token.type != ttKw && token.kw != kwTo) {
        BAD_TOKEN("'to'", token);
        return false;
    }
    Expr right = {0};
    if (!build_expr_ast(lexer, &right)) return false;
    if (!get_token(lexer, &token)) return false;
    if (token.type != ttKw && token.kw != kwDo) {
        BAD_TOKEN("'do'", token);
        return false;
    }
    vec block = {sizeof(Stmt)};
    assert(!block.data && !block.cap && !block.size);
    if (!build_block_ast(lexer, &block)) {
        fprintf(stderr, "Invalid loop body\n");
        return false;
    }
    forLoop->var = var;
    forLoop->left = left;
    forLoop->right = right;
    forLoop->block = block;
    return true;
}
bool build_cond_ast(Lexer *lexer, Conditional *cond){
    Expr expr;
    if (!build_expr_ast(lexer, &expr)) {
        fprintf(stderr, "Invalid expression\n");
        return false;
    }
    Token token;
    if (!get_token(lexer, &token)) return false;
    if (!(token.type == ttKw && token.kw == kwThen)){
        BAD_TOKEN("'then'", token);
        return false;
    }
    vec onThen = {sizeof(Stmt)};
    if (!build_block_ast(lexer, &onThen)) return false;
    cond->cond = expr;
    cond->onThen = onThen;
    // 'else' branch is optional;
    if (!get_token(lexer, &token)) return true;
    if (token.type == ttKw && token.kw == kwElse){
        vec onElse = {sizeof(Stmt)};
        if (!build_block_ast(lexer, &onElse)){
            return false;
        }
        cond->onElse = onElse;
    } else {
        unget_token(lexer, &token);
    }
    return true;
}

bool build_expr_ast(Lexer *lexer, Expr *expr);

bool build_expr_atom(Lexer *lexer, Expr *expr){
    // TODO: negation
    // TODO: function calls
    Token token;
    if (!get_token(lexer, &token)) return false;
    if (token.type == ttBracket && token.br == LeftPar) {
        if (!build_expr_ast(lexer, expr)) return false;
        if (!get_token(lexer, &token)) return false;
        if (!(token.type == ttBracket && token.br == RightPar)) {
            BAD_TOKEN("')'", token);
            return false;
        }
        return true;
    } else if (token.type == ttNumberLit) {
        expr->type = exprNumValue;
        expr->num = token.num;
        return true;
    }
    if (token.type == ttStringLit) {
        expr->type = exprStrValue;
        expr->str = token.str;
        token.str = NULL;
        return true;
    }
    if (token.type == ttIdent){
        expr->type = exprVar;
        expr->str = token.str;
        token.str == NULL;
        if (get_token(lexer, &token) && token.type == ttBracket && token.br == LeftPar) {
            Call call = { .procName = expr->str, {sizeof(Expr)} };
            if (!build_param_list_ast(lexer, &call.params)) {
                fprintf(stderr, "Invalid call");
                return false;
            }
            expr->type = exprCall;
            expr->call = call;
        } else {
            unget_token(lexer, &token);
        }
        return true;
    }
    BAD_TOKEN("number, string or identifier", token);
    return false;
}

bool build_expr_1(Lexer *lexer, Expr* p_lhs, int min_prec, /*out*/ Expr *expr) {
    Expr lhs = *p_lhs;
    Token token;
    if (!get_token(lexer, &token)) return false;
    while (token.type == ttOper && OpPrecedence[token.op] >= min_prec) {
        Operator op = token.op;
        Expr rhs;
        if (!build_expr_atom(lexer, &rhs)) return false;
        while(get_token(lexer, &token) && token.type == ttOper && OpPrecedence[token.op] > OpPrecedence[op]){
            unget_token(lexer, &token);
            Expr new_rhs;
            if (!build_expr_1(lexer, &rhs, OpPrecedence[token.op], &new_rhs)) return false;
            rhs = new_rhs;
            get_token(lexer, &token);
        }
        Expr new_lhs = { .type = exprBinary, .op = op, .lhs = malloc(sizeof(Expr)), .rhs = malloc(sizeof(Expr)) };
        *new_lhs.lhs = lhs;
        *new_lhs.rhs = rhs;
        lhs = new_lhs;
    }
    unget_token(lexer, &token);
    *expr = lhs;
    return true;
}

bool build_expr_ast(Lexer *lexer, Expr *expr){
    Expr lhs;
    if (build_expr_atom(lexer, &lhs)){
        if (!build_expr_1(lexer, &lhs, 0, expr)){
            *expr = lhs;
        }
        return true;
    }
    return false;
}

bool build_param_list_ast(Lexer *lexer, vec* params){
    assert(params->item_size == sizeof(Expr));
    Token token;
    enum {
        WAIT_EXPR_OR_PAREN,
        WAIT_EXPR,
        WAIT_COMMA_OR_PAREN,
    } state = WAIT_EXPR_OR_PAREN;
    while(true) {
        if (!get_token(lexer, &token)) return false;
        switch(state) {
        case WAIT_EXPR_OR_PAREN:
            if (token.type == ttBracket && token.br == RightPar) {
                return true;
            }
            // FALLTHROUGH
        case WAIT_EXPR:
            {
                unget_token(lexer, &token);
                Expr expr;
                if (!build_expr_ast(lexer, &expr)) return false;
                vec_Expr_push(params, expr);
                state = WAIT_COMMA_OR_PAREN;
            }
            break;
        case WAIT_COMMA_OR_PAREN:
            if (token.type == ttBracket && token.br == RightPar) {
                return true;
            }
            if (token.type == ttDelim && token.delim == Comma){
                state = WAIT_EXPR;
            } else {
                BAD_TOKEN("',' or ')'", token);
                return false;
            }
            break;
        }
    }
    return false;
}

typedef struct Visitor Visitor;
#define CAN_VISIT(NODE) void(*visit_##NODE)(Visitor*, NODE*)
struct Visitor{
    CAN_VISIT(Program);
    CAN_VISIT(Proc);
    CAN_VISIT(Arg);
    CAN_VISIT(Stmt);
    CAN_VISIT(Assignment);
    CAN_VISIT(ForLoop);
    CAN_VISIT(Conditional);
    CAN_VISIT(Call);
    CAN_VISIT(Expr);
};
#undef CAN_VISIT

#include "verify_lex_parse.h"

int main(){
    verify_lex_parse("1.input.txt", "1.lex.txt", "1.parse.txt");
    verify_lex_parse("2.input.txt", "2.lex.txt", "2.parse.txt");
    verify_lex_parse("3.input.txt", "3.lex.txt", NULL);
    printf("----------------------\n");
    verify_expr("expr0.input.txt", "expr0.parse.txt");
    verify_expr("expr1.input.txt", "expr1.parse.txt");
    verify_expr("expr2.input.txt", "expr2.parse.txt");
    verify_expr("expr3.input.txt", "expr3.parse.txt");
    verify_expr("expr4.input.txt", "expr4.parse.txt");
    printf("----------------------\n");
}