package com.example.ssl.openapi.generated.model;

import java.net.URI;
import java.util.Objects;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import org.springframework.lang.Nullable;
import org.openapitools.jackson.nullable.JsonNullable;
import java.time.OffsetDateTime;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import io.swagger.v3.oas.annotations.media.Schema;


import java.util.*;
import jakarta.annotation.Generated;

/**
 * TaskItemUpsertPayload
 */

@Generated(value = "org.openapitools.codegen.languages.SpringCodegen", date = "2026-03-20T10:43:47.615777466+01:00[Europe/Madrid]", comments = "Generator version: 7.14.0")
public class TaskItemUpsertPayload {

  private String title;

  private Boolean done = false;

  public TaskItemUpsertPayload() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public TaskItemUpsertPayload(String title) {
    this.title = title;
  }

  public TaskItemUpsertPayload title(String title) {
    this.title = title;
    return this;
  }

  /**
   * Get title
   * @return title
   */
  @NotNull @Size(min = 1, max = 120) 
  @Schema(name = "title", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("title")
  public String getTitle() {
    return title;
  }

  public void setTitle(String title) {
    this.title = title;
  }

  public TaskItemUpsertPayload done(Boolean done) {
    this.done = done;
    return this;
  }

  /**
   * Get done
   * @return done
   */
  
  @Schema(name = "done", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
  @JsonProperty("done")
  public Boolean getDone() {
    return done;
  }

  public void setDone(Boolean done) {
    this.done = done;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    TaskItemUpsertPayload taskItemUpsertPayload = (TaskItemUpsertPayload) o;
    return Objects.equals(this.title, taskItemUpsertPayload.title) &&
        Objects.equals(this.done, taskItemUpsertPayload.done);
  }

  @Override
  public int hashCode() {
    return Objects.hash(title, done);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class TaskItemUpsertPayload {\n");
    sb.append("    title: ").append(toIndentedString(title)).append("\n");
    sb.append("    done: ").append(toIndentedString(done)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
}

