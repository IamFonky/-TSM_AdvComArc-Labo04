# TSM_AdvComArc
## Labo 4 : Security with multi Authentication
__Dylan Canton__
__Pierre-Benjamin Monaco__

### Résumé

Afin de répondre au bonus directement, une implémentation d'UTMS à été faite.
Avec cette implémentation on a alors une autentification mutuelle entre le client et le serveur.

Les fonctions f1,f2,f3,f4,f5,f8,f9 on été implémentées très basiquement et ne sont clairement pas safe mais elle font le travail pour ce labo.

### Instalation
Installer les modules suivants

```bash
pip3 install pycrypto
```

### Utilisation

Pour tester le programme avec un fichier de 32B (~250bit) il suffit de lancer deux terminaux :

__Terminal 1__
``` bash
python3 UMTS.py server minifile output.server
```
__Terminal 2__
``` bash
python3 UMTS.py client minifile output.client
```

Il est aussi possible de tester avec des fichiers plus lourds en input comme UMTS.py ou README.md
``` bash
python3 UMTS.py client UMTS.py output.client
```
