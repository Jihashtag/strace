# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: jbert <jbert@student.42.fr>                +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2016/11/10 13:25:20 by jbert             #+#    #+#              #
#    Updated: 2016/11/10 13:27:32 by jbert            ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

.PHONY: all clean fclean re

NAME	= ft_strace

SRC	=	strace.c
OBJ	=	strace.o

$(NAME):
	gcc -Wall -Wextra -Werror -c $(SRC)
	gcc -Wall -Wextra -Werror -o $(NAME) $(OBJ)

all: $(NAME)

clean:
	rm $(OBJ)

fclean:
	rm $(OBJ) $(NAME)

re: fclean all
