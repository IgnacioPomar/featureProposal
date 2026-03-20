package com.example.ssl.crud;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class TaskItemService {

    private final TaskItemRepository repository;

    public TaskItemService(TaskItemRepository repository) {
        this.repository = repository;
    }

    public TaskItem create(String title, Boolean done) {
        TaskItem entity = new TaskItem();
        entity.setTitle(normalizeTitle(title));
        entity.setDone(Boolean.TRUE.equals(done));
        return repository.save(entity);
    }

    @Transactional(readOnly = true)
    public TaskItem getById(UUID id) {
        return findEntity(id);
    }

    @Transactional(readOnly = true)
    public List<TaskItem> listAll() {
        return repository.findAll();
    }

    public TaskItem update(UUID id, String title, Boolean done) {
        TaskItem entity = findEntity(id);
        entity.setTitle(normalizeTitle(title));
        entity.setDone(Boolean.TRUE.equals(done));
        return repository.save(entity);
    }

    public void delete(UUID id) {
        TaskItem entity = findEntity(id);
        repository.delete(entity);
    }

    private TaskItem findEntity(UUID id) {
        return repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Task not found: id=" + id));
    }

    private String normalizeTitle(String title) {
        if (title == null) {
            return "";
        }
        return title.trim();
    }
}
