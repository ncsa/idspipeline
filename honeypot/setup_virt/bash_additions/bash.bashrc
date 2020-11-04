export PROMPT_COMMAND='history -a >(tee -a ~/.bash_history | xargs -I {} logger -p local6.debug -t "bash_history[$$]" "[user:$USER] {}")'
