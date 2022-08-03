package bluebird.emm.authorization.entity;

import lombok.Getter;
import lombok.ToString;

import javax.persistence.*;

@Getter
@ToString
@Entity
@Table(name = "users", indexes = @Index(name = "idx_email", columnList = "email"))
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String firstName;
    private String lastName;
    @Column(unique = true)
    private String email;

    @Column(length = 60)
    private String password;

    private String role;
    private boolean enabled;

}
