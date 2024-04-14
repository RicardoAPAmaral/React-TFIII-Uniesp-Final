package br.com.diegopatricio.servicex.ordemservico.repositories;


import br.com.diegopatricio.servicex.categoria.domain.Categoria;
import br.com.diegopatricio.servicex.ordemservico.domain.OrdemServico;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;



@Repository
public interface OrdemServicoRepository extends JpaRepository<OrdemServico, Integer> {

}
