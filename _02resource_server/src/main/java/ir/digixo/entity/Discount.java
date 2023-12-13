package ir.digixo.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.LocalDate;

@Entity
@Setter
@Getter
@AllArgsConstructor
@RequiredArgsConstructor
@ToString
@Table(name = "coupon")
public class Discount {


    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE,generator = "discount_seq")
    @SequenceGenerator(name = "discount_seq",allocationSize = 10)
    private Long id;
    private String code;
    private BigDecimal discount;
    @JsonProperty("date")
    @Column(name = "expiry_date")
    private LocalDate expiryDate;


}
