O teste avaliou a rede de laboratório **10.10.10.0/28** (exceto o gateway 10.10.10.1). Foram encontrados **2 problemas críticos/altos que, juntos, dão acesso total aos dados da intranet** sem precisar de nenhuma senha:

- o **Redis** responde a qualquer um na rede, sem autenticação;
- o **FTP anônimo** entrega um backup com a senha do banco de dados.

Recomendamos, nesta ordem: fechar o Redis e o FTP anônimo hoje, trocar a senha do banco e, em seguida, desativar o SMBv1 e exigir assinatura SMB no servidor de arquivos.
