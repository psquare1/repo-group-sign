echo "0xPARC" | ssh-keygen -Y sign -n file -f ~/.ssh/github > content.sig
echo "0xPARC" | ssh-keygen -Y sign -n file -f key > ed25519.sig