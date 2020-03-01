package main

import (
	"errors"
	"log"
	"sync"
)

type Task struct {
	Id         uint   `json:"id"`
	OrderLogin string `json:"orderLogin"`
	Title      string `json:"title"`
	Text       string `json:"text"`
	Tag        string `json:"tag"`
	Time       string `json:"time"`
}

type TaskTable struct {
	mapTask map[string]*Task
	mu      sync.RWMutex
	nextID  uint
}

func NewTaskTable() *TaskTable {
	return &TaskTable{
		mu:      sync.RWMutex{},
		mapTask: make(map[string]*Task),
	}
}

func (taskTable *TaskTable) AddTask(newTask *Task) (uint, error) {
	log.Println("Add Task called")

	_, exist := taskTable.mapTask[newTask.OrderLogin]
	if exist == true {
		return 0, errors.New("task title already exist")
	}

	taskTable.mu.Lock()
	taskTable.nextID++
	newTask.Id = taskTable.nextID
	taskTable.mapTask[newTask.OrderLogin] = newTask
	taskTable.mu.Unlock()

	return newTask.Id, nil
}

func (taskTable *TaskTable) SetSomeStartTask() {

	//1
	task1 := new(Task)
	task1.OrderLogin = "name1"
	task1.Tag = "c++"
	task1.Text = "1 i need some code.... i need some code.... i need some code.... i need some code.... " +
		"i need some code.... i need some code.... i need some code.... i need some code.... i need some code....  "
	task1.Time = "23.5.2020"
	task1.Title = "task title 1"

	//2
	task2 := new(Task)
	task2.OrderLogin = "name 2"
	task2.Tag = "python"
	task2.Text = "2 i need some code.... i need some code.... i need some code.... i need some code.... " +
		"i need some code.... i need some code.... i need some code.... i need some code.... i need some code....  "
	task2.Time = "23.3.2020"
	task2.Title = "task title 2"

	//3
	task3 := new(Task)
	task3.OrderLogin = "name 3"
	task3.Tag = "js"
	task3.Text = "3 i need some code.... i need some code.... i need some code.... i need some code.... " +
		"i need some code.... i need some code.... i need some code.... i need some code.... i need some code....  "
	task3.Time = "2.5.2020"
	task3.Title = "task title 3"

	taskTable.AddTask(task1)
	taskTable.AddTask(task2)
	taskTable.AddTask(task3)

}

func (taskTable *TaskTable) GetTasks(size int) ([]Task, error) {

	var tasks []Task
	curSize := 0
	for _, task := range taskTable.mapTask {
		if curSize == size {
			break
		}
		tasks = append(tasks, *task)
		curSize++
	}

	// if zero task -> return err

	return tasks, nil
}

func (taskTable *TaskTable) GetOneTask(id int) (*Task, error) {

	for _, task := range taskTable.mapTask {
		if int(task.Id) == id {
			return task, nil
		}
	}

	return nil, errors.New("not have task with this id")
}
