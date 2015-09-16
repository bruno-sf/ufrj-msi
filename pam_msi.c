/*
* 	pam_msi.c - método alternativo para autenticação.
*	resumo:Documentação em https://github.com/bruno-sf/ufrj-msi
*	email:brunoferreira@ufrj.br
*/

#define _XOPEN_SOURCE       /* Necessário para uso do crypt */
#define PAM_SM_AUTH /* Define qual interfcace PAM será provido */
#include <security/pam_modules.h> /* Inclui PAM headers */
#include <security/_pam_macros.h>
#include <security/pam_misc.h>
#include <unistd.h>
#include <crypt.h>

/*
*
*	INÍCIO Configuração
*
*/
int	usuario_qtd_pares=4;
int	usuario_ordem_categ[]={3,2,5,4};
int	usuario_qtd_categ[]={3,3,3,3};
char	*salt="32";
char 	*arquivo_senha="/home/brunof/.pam.msi";
/*
*
*	FIM Configuração
*
*/


/*
*	
*	INICIO SEÇÃO DE VARIÁVEIS E STRUCTS
*
*/

int	retval;
char *usuario, *senha, *criptografado, *p;
enum
{
	C_INVAL = 1,
	C_MAIUSC,
	C_MINUSC,
	C_SIMB,
	C_NUM
};

typedef struct
{
	int	cont;
	int	categ;

}	PAR;

PAR pares[99];

/*
Tabela ISO 8859-1
0-32-Inválidos
33-47-Símbolos parte1
48-57-Numeros
58-64-Símbolos parte2
65-90-Letras Mai
91-96-Símbolos parte3
97-122-Letras Min
123-126-Símbolos parte4
127-255-Inválidos
*/

int tabela[256] =
{
	C_INVAL,
	C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,
	C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_SIMB,

	C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_NUM,

	C_NUM,C_NUM,C_NUM,C_NUM,C_NUM,C_NUM,C_NUM,C_NUM,C_NUM,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,

	C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,

	C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_MAIUSC,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_SIMB,

	C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,

	C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_MINUSC,C_SIMB,C_SIMB,C_SIMB,C_SIMB,C_INVAL,C_INVAL,

	C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,
	C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,

	C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,
	C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,

	C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,
	C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,

	C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,
	C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,C_INVAL,

};

/*
*	
*	FIM SEÇÃO DE VARIÁVEIS E STRUCTS
*
*/

/* 
*
*	INÍCIO DA SEÇÃO DE FUNÇÕES
*
*/

void fn_gera_pares (char *senha)
{
	char *p;
	int ind_pares = 0;
	pares[0].categ = C_INVAL;

	for (p = senha; *p != '\0'; p++)
	{
		int categ = tabela[*p];

		if (categ == C_INVAL)
		{
			fprintf (stderr, "[ERRO]:Caractere inválido\n");
			retval = PAM_AUTH_ERR;
			break;
		}

		if (categ == pares[ind_pares].categ)
		{
			pares[ind_pares].cont++;
		}
		else
		{
		

			ind_pares++;
			if (ind_pares > 98)
			{
				fprintf (stderr, "[ERRO]:Senha invalida\n");
				retval = PAM_AUTH_ERR;
				break;
			}
			pares[ind_pares].cont = 1;
			pares[ind_pares].categ = categ;
		}

	} // Fim do for

	/* Verificando qtd de pares se é igual a pré definida pelo usuário. Senão sai */
	int total_pares = ind_pares;
	int i; // Primeiro par 
	if ( total_pares != usuario_qtd_pares)
	{
		printf("[ERRO]:Acesso negado!\n");
		retval = PAM_AUTH_ERR;

	}
	else
	{

//	 olhar o vetor a partir da posicao 1, ignorar a 0 */
	for (i = 1; i < total_pares+1; i++)
	{
		if ( pares[i].categ != usuario_ordem_categ[i-1] )
		{

			retval = PAM_AUTH_ERR;
		}
		else
		{
			if ( pares[i].cont != usuario_qtd_categ[i-1] )
			{
			retval = PAM_AUTH_ERR;
			}

		}
		}
	} // fim do for

} //fim função gera_pares

//Inicio funcao verifica pwd existe
int fn_ver_pwd ( char *arquivo_senha, char *usuario, char *criptografado ){
	char buf[BUFSIZ]; /* File input buffer */
	char *arq_usuario, *arq_senha; /* Buffers para os valores dentro do arquivo */
	FILE *fd;
	if((fd = fopen(arquivo_senha, "r")) == NULL)
	{
		printf("\n[ERRO]:Erro ao abrir arquivo!\nAbortando...\n");
		retval = 1;
	} 
	else 
	{
	/* Loop no arquivo de senhas */

		while (!feof(fd)) 
		{
		/* Inicializa com string vazia */
		buf[0] = '\0';

		/* Lê em uma linha */
		fscanf(fd, "%s", buf);

		/* Se a linha for vazia, continua */
		if(strlen(buf) == 0) continue;

			/* Ponteiro para o buffer */
			arq_usuario = buf;

			/* Ponteiro para o delimitador dentro do buffer */
			arq_senha = strchr(buf, ':');

			/* Troca o delimitador para caracter nul */
			arq_senha[0] = '\0';

			/* Move para o próximo caracter */
			arq_senha++;
			
			/* Verifica se corresponde com o nome de usuário entrado */
			if(strcmp(arq_usuario, usuario) == 0)
			{
				/* Verifica se a senha já existe */
				if(strcmp(criptografado, arq_senha) == 0)
				{
					retval = PAM_AUTH_ERR;
					break;
					/* Senha encontrada, cai fora do loop */

				} 
				else 
				{
					retval = PAM_SUCCESS;	//senha nova
				} /* Fim do if */
			} /* Fim do if */
			else
			{
				//Usuário diferente ou inválido.
				retval = PAM_USER_UNKNOWN;
			}
		} /* Fim do while */
				
	} /* Fim do if */

	fclose(fd);/* Fecha o arquivo */

return retval;
} //fim da funcão verifica pwd anterior



//Início função grava pwd
int fn_grava_pwd ( char *arquivo_senha, char *usuario, char *criptografado) {

	//Verifica se o arquivo existe

	if( access( arquivo_senha, F_OK ) != -1 ) 
	{
	    // Arquivo pwd já existe
		FILE  *fd;
    		fd = fopen(arquivo_senha, "a");
		fprintf(fd, "%s:%s\n", usuario, criptografado);
		fclose(fd);
		retval = PAM_SUCCESS;
	} 
	else 
	{
	    // Arquivo não existe
		FILE  *fd;
    		fd = fopen(arquivo_senha, "w");
		fprintf(fd, "%s:%s\n", usuario, criptografado);
		fclose(fd);
		retval = PAM_SUCCESS;
	}

return retval;
}//Fim função grava pwd

int fn_criptografa_pw ( char *senha ) {
	char	*p;
	criptografado = (char *) crypt(senha, salt);
	for (p = senha; *p != '\0'; )
	{
        *p++ = '\0';

		if (criptografado == NULL)
		{
			retval = 1;
			printf("[ERRO]:Não foi possível criptografar a senha.");
		}
		else
		{
			retval = 0;
		}
	}
return retval;
} //Fim função criptografa

/* 
*
*	FIM DA SEÇÃO DE FUNÇÕES
*
*/

/*
*	
*	INICIO DO CÓDIGO PRINCIPAL
*
*/
  /* Verificação de autenticação do PAM*/
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	//Pegando o usuário
	if(pam_get_item(pamh, PAM_USER, (const void **)(const void*)&usuario)!= PAM_SUCCESS) { retval = PAM_USER_UNKNOWN; };
	//chama função gera pares
	senha = getpass("Password2: ");
	fn_gera_pares(senha);

	if ( retval != 0 )
	{
		return retval;
		exit( EXIT_FAILURE );
	}

	fn_criptografa_pw(senha);	

	if ( fn_ver_pwd( arquivo_senha, usuario,criptografado ) != 0 )
	{	
		printf("[ERRO]:Acesso negado.\n"); //Senha já foi digitado
	}
	else
	{
		if ( fn_grava_pwd( arquivo_senha, usuario, criptografado ) != 0 )
		{	
			printf("[ERRO]:Falha ao gravar senha no arquivo: %s", arquivo_senha);			
			retval = 1;
			exit ( EXIT_FAILURE );
		}
		else
		{
			retval = PAM_SUCCESS;
		}
	
	}

	return( retval );
	exit( EXIT_SUCCESS );
}
