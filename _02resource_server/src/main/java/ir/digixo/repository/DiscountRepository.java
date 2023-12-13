package ir.digixo.repository;


import ir.digixo.entity.Discount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DiscountRepository extends JpaRepository<Discount,Long> {

    Optional<Discount> findByCode(String code);
}
