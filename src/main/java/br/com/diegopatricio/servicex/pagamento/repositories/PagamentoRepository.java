package br.com.diegopatricio.servicex.pagamento.repositories;

import br.com.diegopatricio.servicex.pagamento.domain.Pagamento;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PagamentoRepository extends JpaRepository<Pagamento, Integer> {
}
