git switch -c $1
git push -u upstream $1
GIT_NO_LAZY_FETCH=0 git fetch --all
git log --oneline --no-merges main/mybranch
