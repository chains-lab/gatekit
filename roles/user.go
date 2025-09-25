package roles

import "fmt"

const (
	Admin = "admin"
	Moder = "moderator"
	User  = "user"
)

var rolesAllowed = []string{
	Admin,
	Moder,
	User,
}

var ErrorRoleNotSupported = fmt.Errorf("role must be one of: %s", GetAllRoles())

func ParseRole(i string) error {
	for _, role := range rolesAllowed {
		if role == i {
			return nil
		}
	}

	return fmt.Errorf("'%s', %w", i, ErrorRoleNotSupported)
}

// CompareRolesUser
// res : 1, if first role is higher priority
// res : -1, if second role is higher priority
// res : 0, if roles are equal
func CompareRolesUser(role1, role2 string) (int, error) {
	err := ParseRole(role1)
	if err != nil {
		return -1, err
	}

	err = ParseRole(role2)
	if err != nil {
		return -1, err
	}

	priority := map[string]int{
		Admin: 3,
		Moder: 2,
		User:  1,
	}

	p1, ok1 := priority[role1]
	p2, ok2 := priority[role2]

	if !ok1 || !ok2 {
		return -1, nil
	}

	if p1 > p2 {
		return 1, nil
	} else if p1 < p2 {
		return -1, nil
	}
	return 0, nil
}

func GetAllRoles() []string {
	return rolesAllowed
}
