CC=chmod

all: rawhttpget set_iptable restore_iptable get_txt get_webpage

rawhttpget: Makefile
	${CC} 775 ./rawhttpget

set_iptable: Makefile
	${CC} 775 ./set_iptable

restore_iptable: Makefile
	${CC} 775 ./restore_iptable

get_txt: Makefile
	${CC} 775 ./get_txt

get_webpage: Makefile
	${CC} 775 ./get_webpage

clean:
	rm -f ./*.pyc	
