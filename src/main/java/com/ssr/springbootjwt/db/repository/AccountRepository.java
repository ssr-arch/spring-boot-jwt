package com.ssr.springbootjwt.db.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.ssr.springbootjwt.db.entity.Account;

@Repository
public interface AccountRepository extends CrudRepository<Account, Integer> {

    Account findByName(String name);

    List<Account> findAll();

}
