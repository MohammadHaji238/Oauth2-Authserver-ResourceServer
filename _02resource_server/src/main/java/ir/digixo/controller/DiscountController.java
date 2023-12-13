package ir.digixo.controller;


import ir.digixo.entity.Discount;
import ir.digixo.repository.DiscountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/v1/discounts")
public class DiscountController {


    @Autowired
    private DiscountRepository discountRepository;


    /*
    {
    "code":"spring10",
    "discount":"10",
    "date":"2023-05-04"
}
    * */
    @PostMapping
    public Discount createDiscount(@RequestBody Discount coupon)
    {
        return   discountRepository.save(coupon);
    }
    @GetMapping("{code}")
    public Discount findByCouponCode(@PathVariable("code") String discount)
    {
        System.out.println("service invoked!!");
        Optional<Discount> discount1 = discountRepository.findByCode(discount);
       return discount1.orElse(null);
       //return coupon1.or();
       // return coupon1.isPresent() ? coupon1.get() : null;
    }
}
