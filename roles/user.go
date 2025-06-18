package roles

import "fmt"

type Role string

// TODO in future maybe add service role
const (
	SuperUser Role = "super_user"
	Admin     Role = "admin"
	User      Role = "user"
)

func ParseRole(i string) (Role, error) {
	switch i {
	case "super_user":
		return SuperUser, nil
	case "admin":
		return Admin, nil
	case "user":
		return User, nil
	default:
		return "", fmt.Errorf("incorect Role type")
	}
}

// CompareRolesUser
// res : 1, if first role is higher priority
// res : -1, if second role is higher priority
// res : 0, if roles are equal
func CompareRolesUser(role1, role2 Role) int {
	priority := map[Role]int{
		SuperUser: 3,
		Admin:     2,
		User:      1,
	}

	p1, ok1 := priority[role1]
	p2, ok2 := priority[role2]

	if !ok1 || !ok2 {
		return -1
	}

	if p1 > p2 {
		return 1
	} else if p1 < p2 {
		return -1
	}
	return 0
}
