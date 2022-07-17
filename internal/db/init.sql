create table users
(
    id       serial
        constraint users_pk
            primary key,
    login    varchar(40)  not null,
    password varchar(256) not null
);

create unique index users_id_uindex
    on users (id);

create unique index users_login_uindex
    on users (login);