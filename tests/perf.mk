REPEAT=1000

OS!= uname -s
.if ${OS} == "Linux" 
run-perftests: .PHONY
	@echo "=> '${PROG}' crypto disabled"
	@perf stat -r ${REPEAT} -e cycles,instructions \
		${.CURDIR}/${PROG} "key-foo-perf" "value-bar-perf" 2>&1 | grep -v "=>"
	@echo "=> '${PROG}' crypto enabled"
	@CRYPTREDISKEY=41d962ad5479795a10de0a369dea3b1e \
		perf stat -r ${REPEAT} -e cycles,instructions \
		${.CURDIR}/${PROG} "key-foo-perf" "value-bar-perf" 2>&1 | grep -v "=>"
.else
run-perftests: .PHONY
	@echo "make sure linux 'perf tool' is installed"
.endif

# vim: set ts=8 sw=8 noet:
