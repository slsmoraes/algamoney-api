package com.example.algamoney.api.service;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import com.example.algamoney.api.model.Categoria;
import com.example.algamoney.api.repository.CategoriaRepository;

@Service
public class CategoriaService {
	
	@Autowired
	private CategoriaRepository categoriaRepository;

	public Categoria atualizar(Long codigo, Categoria categoria) {
		Categoria categoriaSalva = buscarCategoriaPeloCodigo(codigo);
		
		BeanUtils.copyProperties(categoria, categoriaSalva, "codigo");
		return categoriaRepository.save(categoriaSalva);
	}
	
	public Categoria buscarCategoriaPeloCodigo(Long codigo) {
		Categoria categoriaSalva = categoriaRepository.findById(codigo).get();
		if (categoriaSalva == null) {
			throw new EmptyResultDataAccessException(1);
		}
		return categoriaSalva;
	}	
}
