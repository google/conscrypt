git cherry-pick $1 -X ours
git rm -r repackaged
git-clang-format 
git add .
git push -u upstream $2
