GIT
---------------
1. What is git reset ? Types of reset ?hard, soft and mixed
2. How to delete local branch  and remote branch in git ? 
  git push origin -d kesh --->to dlete remote branch
  git branch -d kesh -->to delete local branch
4. Difference between git diff and git status ?
5. What are hooks in git? 
  hooks are ordinary scripts this will execute when a event occur in repository
  webhooks are for web applications. it will trigger when ever there are any changes in code. same like hooks but these are for web apps.

MAVEN
--------
5. What are things you need to set, if you want download dependency from private repository ?
6. What are the issues you faced while working on maven projects?
7. Command to skip the test cases in maven

JENKINS
----------
8. How to set Jenkins build to fail based specific word in console output ?--------------use grep command in scripted pipeline stage and steps
9. What are active and reactive parameters (Dynamic parameterization) in Jenkins ?
10. How to customize the build number display to something else in Jenkins job page?
11. What are multi branch pipeline?
12. What is shared library in Jenkins ?-----------collection of independent groovy scripts which can be stored in git repo and can be used in pulling the code into jenkinsfile in runtime


UNIX & SHELL SCRIPTING
-----------
13. Command to find empty files in a given directory?
14. Commands you will use it for configuring ssh connectivity between 2 machines and what files will be present in .ssh folder?
15. How to schedule a shell script in unix machines?
16. Command to get load average ?
17. Need to identify ip addresses in log file and count of ip addresses in log file?

ANSIBLE
------------
18. Why ansible ? What makes ansible powerful than other tools like chef and puppet?
19. 5 modules that you have worked on? Can we create custom module ?
20. What is dynamic inventory in ansible?---> it is inventory control managemt system to provide inventory control and manages features
21. Lets say I have both Ubuntu and centos machines as nodes I want install application tree using same playbook, how would you approach this scenario? 
22. How to handle prompts with ansible playbook?

DOCKER
----------
23. What does ONBUILD instruction do in Dockerfile?--> it will add instruction to image like a special instuction to build on later time
25. What is the use of .dockerignore file?--> to ignore files when you try to build a docker image
27. I have dockerfile that accepts arguments, if I supply value as “1” then it should use maven 2.x version for base image and if I supply “2” then it should take maven latest as base image 
28. What are docker compose and docker swarm?---> docker compose will run multiple containers on same host but docker swarm is container orchestration which runs multiple containers on diff hosts

KUBERNETES
---------
27. Components in kubernetes architecture?
28. What are stateful sets in kuberentes?
29. Command to find which container has failed in pod and command to get logs of container 
30. Tools to maintain kubernetes log files 

AWS
-----
31. Services used AWS and tasks performed in AWS
