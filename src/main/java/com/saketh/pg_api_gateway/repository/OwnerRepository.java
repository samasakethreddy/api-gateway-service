package com.saketh.pg_api_gateway.repository;

import com.saketh.pg_api_gateway.entity.Owner;
import com.saketh.pg_api_gateway.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OwnerRepository extends JpaRepository<Owner, Long> {
    Optional<Owner> findByEmail(String email);
}

