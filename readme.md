# Doug's DB
This is a small, simple, key-value database written in C, built on top of https://github.com/douglasmaieski/green-threads-workers

I'm planning to use it for web projects.

**Note: there are bugs**

## How it works
- The keys are hashed and stored in a binary tree
- There's a file with all the DB content
- Every `upsert` or `delete` allocates memory for the node and its contents
- The holes in the DB have to be reclaimed by the (TODO) defragmenter

## Performance
I have yet to test it on a good computer, but my tests showed decent performance.

## TODO
1. Write a defragmenter
2. Allow iterating in asc/desc order
3. Improve write performance
