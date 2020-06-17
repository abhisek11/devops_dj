#!/bin/sh

setup_git() {
  git config --global user.email "travis@travis-ci.org"
  git config --global user.name "Travis CI"
}

commit_website_files() {
  git checkout $TRAVIS_BRANCH
  git add deploy/v2/app
  git commit --message "Travis build $VER"
}

upload_files() {
  git remote add origin https://ankitk1989:$GH_TOKEN@github.com/SecureYourInbox/brandsecure-backend.git > /dev/null 2>&1
  git push origin $TRAVIS_BRANCH
}

setup_git
commit_website_files
upload_files
