package service

const (
	FACTORY_TYPE_IDENTITY_PROVIDER = "factory.type.identity.provider"
)

/*
Steps for adding a new Service:
1. Add a new service interface to application/service/services.go
2. Create an implementation of the service interface
3. Add a new method to service.Services interface in application/service/services.go for accessing the service interface
   defined in step 1
4. Add a new method to application/service/factory/service_factory.go which implements the service access method
   from step #3 and uses the service constructor from step 2
5. Add a new method to gormapplication/application.go which implements the service access method from step #3
   and use the factory method from the step #4
*/

// Services creates instances of service layer objects
type Services interface {
}

//----------------------------------------------------------------------------------------------------------------------
//
// Factories are a special type of service only accessible from other services, that can be replaced during testing,
// in order to produce mock / dummy factories
//
//----------------------------------------------------------------------------------------------------------------------

// Factories is the interface responsible for creating instances of factory objects
type Factories interface {
}
