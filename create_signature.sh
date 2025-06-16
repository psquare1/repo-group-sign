echo "0xPARC" | ssh-keygen -Y sign -n file -f ~/.ssh/github > content.sig
echo "0xPARC" | ssh-keygen -Y sign -n file -f key > ed25519.sig

ssh-keygen -t ed25519 -a 100 -C "duruozer13@gmail.com" -f ~/.ssh/github_ed25519
echo "0xPARC" | ssh-keygen -Y sign -n file -f ~/.ssh/github_ed25519 > github_ed25519.sig