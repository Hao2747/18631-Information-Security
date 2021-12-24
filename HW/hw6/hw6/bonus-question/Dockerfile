FROM ocaml/opam:debian

ENV DEBIAN_FRONTEND="noninteractive"

RUN opam depext conf-graphviz &&\
    opam depext proverif &&\
    opam install proverif
