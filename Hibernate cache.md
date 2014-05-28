Одной из основных возможностей Hibernate является использование кэша. При правильной настройке это может давать достаточно большой прирост производительности засчёт сокращения количества запросов к БД. Кэш содержит в себе локальную копию данных, которая может сохраняться в памяти либо на диске (имеет смысл, когда приложение и база данных распологаются на разных физических машинах).

Hibernate обращается к кэшу в следующих случаях:
•	Приложение выполняет поиск сущности по идентификатору
•	Приложение выполняет ленивую загрузку коллекции

Кэши разделяются в зависимости от области видимости (scope) на следующие виды:
•	Transaction scope cache (Кэш привязанный к транзакции, действительный только пока транзакция не завершиться. Каждая транзакция имеет свой кэш, следовательно, доступ к данному кэшу не может быть осуществлён в несколько потоков)
•	Process scope cache (Кэш привязанный к определённому процессу конкретной JVM и общий для многих транзакций с возможностью параллельного доступа)
•	Cluster scope cache (Кэш, общий для нескольких процессов на одной машине или нескольких машин в составе кластера).

По сути, Transaction scope cache представляет собой кэш первого уровня hibernate, кэш же второго уровня может быть реализован либо в области видимости процесса илибо как распределённый кэш. Ниже подробенее рассмотрим работу кэша первого и второго уровня.

Кэш первого уровня

Кэш первого уровня в hibernate связан с объектом сессии, он включёно по умолчанию и нет возможности отключить его. Когда вы передаёте объект в метод save(), update() или saveOrUpdate(), а так же когда пытаетесь обратиться к нему с помощью методов load(), get(), scroll(), list(), iterate() выполняется добавление элемента в кэш сессии и следующий раз, когда нужно будет произвести повторную выборку данного объекта из БД в текущей сессии обращения к БД уже не произойдёт. Объект будет взят из кэша.

Обнуление кэша происходит после закрытия сессии. Так же, содержимым кэша можно управлять используя методы класса Session:
•	contains()  - проверяет сохранён ли объект в кэше
•	flush() - синхронизирует содержимое кэша с базой данных
•	evict() - удаляет объект из кэша
•	clear() - обнуляет кэш.	

Кэш второго уровня

Кэш второго уровня в hibernateможет быть настроен как кэш процесса или как распеределённый кэш (в рамках JVM или кластера). В отличие от кэша первого уровня, использование кэша второго уровня является опциональным. Он может быть как включён так и отключён.
В кэше второго уровня сущности хранятся в разобранном состоянии (что-то наподобие сериализованного состояния, однако, используемый алгоритм намного быстрее сериализации). Соответственно, доступ к объектам, сохранённым в кэше второго уроня осуществляется не по сслыке, а по значению. Обусловлено это ещё и тем, что доступ к сущности может осуществляться из параллельных транзакций. Так, каждая транзакция будет иметь свою копию данных. 
Учитывая вышеперечисленное были разработаны следующие стратегии паралельного доступа к кэшу второго уровня:
•	read only - используется для данных, которые часто читаются но никогда не изменяются
•	nonstrict read write - используется для данных, которые изменяются очень редко. При параллельном доступе к данным из разных транзакций не даёт никакой гарантии, что в кэше будут сохранены актуальные данные, так как при изменении данные не блокируются для чтения. Не слудует использовать данную стратегию, если небольшая вероятность считывания устаревших данных критична для приложения
•	read write - используется для данных которые гораздо чаще читаются, чем обновляются, однако, устаревание которых критично для приложения. В данной стратегии данные блокируются для чтения при их изменении. Данная стратегия обеспечивает уровень изоляции транзакций read commited.
•	transactional - используется, когда необходима изоляция транзакций вполоть до уровня repeatable read. Так же как и предыдущие используется для данных, которые гораздо чаще читаются нежели обновляются.

Вообще, кэш второго уровня не рекомендуется использовать для данных, которые должны изменяться слишком часто, так как затраты производительности на поддержание актуальности кэша могут оказаться больше чем прирост производительности от использования кэша.
Ни одна из вышеперечисленных стратегий не реализуется самим хибернэйтом. Для этого используются провайдеры кэша, основные из которых:
•	EhCache - раньше поддерживал только кэш уровня процесса, но с последних версий поддерживает так же распределённый кэш. Имеется поддрержка кэша запросов и выгрузки данных на диск.
•	OpenSymphony OSCache - поддерживает кэш только на уровне процесса. Поддерживает кэш запросов и выгрузку данных на диск
•	SwarmCache - распределённый кэш, который базирется на JGroups. Нет поддержки кэша запросов
•	JBoss Cache - 
