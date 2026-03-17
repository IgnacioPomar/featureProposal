package com.example.ssl.crud;

import com.example.ssl.openapi.generated.api.TasksApi;
import com.example.ssl.openapi.generated.model.TaskItemPayload;
import com.example.ssl.openapi.generated.model.TaskItemUpsertPayload;
import java.net.URI;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.openapitools.jackson.nullable.JsonNullable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TaskGeneratedApiController implements TasksApi {

    private final TaskItemService service;

    public TaskGeneratedApiController(TaskItemService service) {
        this.service = service;
    }

    @Override
    public ResponseEntity<TaskItemPayload> createTask(TaskItemUpsertPayload request) {
        TaskItem entity = service.create(request.getTitle(), request.getDone());
        TaskItemPayload body = toPayload(entity);
        return ResponseEntity.created(URI.create("/api/tasks/" + body.getId())).body(body);
    }

    @Override
    public ResponseEntity<Void> deleteTask(UUID id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }

    @Override
    public ResponseEntity<TaskItemPayload> getTaskById(UUID id) {
        return ResponseEntity.ok(toPayload(service.getById(id)));
    }

    @Override
    public ResponseEntity<List<TaskItemPayload>> listTasks() {
        List<TaskItemPayload> tasks = service.listAll().stream().map(this::toPayload).toList();
        return ResponseEntity.ok(tasks);
    }

    @Override
    public ResponseEntity<TaskItemPayload> updateTask(UUID id, TaskItemUpsertPayload request) {
        TaskItem entity = service.update(id, request.getTitle(), request.getDone());
        return ResponseEntity.ok(toPayload(entity));
    }

    private TaskItemPayload toPayload(TaskItem entity) {
        TaskItemPayload payload = new TaskItemPayload(
                entity.getId(),
                entity.getTitle(),
                entity.isDone(),
                entity.getCreatedAt()
        );

        OffsetDateTime updatedAt = entity.getUpdatedAt();
        if (updatedAt == null) {
            payload.setUpdatedAt(JsonNullable.undefined());
        } else {
            payload.setUpdatedAt(JsonNullable.of(updatedAt));
        }
        return payload;
    }
}
