"""Define the adapter of the Auth store."""

import logging
from contextlib import suppress
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from goodconf import GoodConf
from pydantic import BaseModel, EmailStr, Field  # noqa: E0611
from ruyaml import YAML

from ..exceptions import NotFoundError, TooManyError
from .key import GPGKey

Name = str
Username = Name
Identifier = Name
GPGIDPath = str


log = logging.getLogger(__name__)


class Group(BaseModel):
    """Model a group of users."""

    name: Name
    users: List[EmailStr] = Field(default_factory=list)

    def match(self, other: Union[str, "Group", "User"]) -> bool:
        """Check if the group or it's users matches other object."""
        if isinstance(other, str):
            return other == self.name or other in self.users
        if isinstance(other, User):
            return other.email in self.users
        return other == self

    def add_users(self, users: List["User"]) -> bool:
        """Add a list of users from the group.

        Returns:
            If there was any user added.
        """
        changed = False

        for user in users:
            if user.email not in self.users:
                log.info(f"Adding user {user.name} to group {self.name}")
                self.users.append(user.email)
                changed = True

        return changed

    def remove_users(self, users: List["User"]) -> bool:
        """Remove a list of users from the group.

        Returns:
            If there was any user removed.
        """
        changed = False
        for user in users:
            log.info(f"Removing user {user.name} from group {self.name}")
            try:
                self.users.remove(user.email)
                changed = True
            except ValueError:
                log.info(f"User {user.name} is not part of the {self.name} group")

        return changed


class User(BaseModel):
    """Model a user of the password store."""

    name: Username
    email: EmailStr
    key: GPGKey

    def match(self, other: Union[str, "Group", "User"]) -> bool:
        """Check if the user matches the identifier."""
        if isinstance(other, str):
            return other in (self.name, self.key, self.email)
        return False


class AuthStore(GoodConf):
    """Define the adapter of the authorisation store."""

    groups: List[Group] = Field(default_factory=list)
    users: List[User] = Field(default_factory=list)
    access: Dict[GPGIDPath, List[Identifier]] = Field(default_factory=dict)

    def add_user(self, name: str, key: str, email: str) -> User:
        """Create a new user.

        Args:
            name: name of the user
            key: GPG key of the user.
            email: Email of the user.

        Raises:
            ValueError: if the user already exists
        """
        for id_, value in [("name", name), ("key", key), ("email", email)]:
            with suppress(NotFoundError):
                user = self.get_user(value)
                if user:
                    raise ValueError(
                        f"The user {user.name} is using the {id_} {value}."
                    )

        new_user = User(name=name, key=key, email=EmailStr(email))
        self.users.append(new_user)
        self.save()
        return new_user

    def add_group(self, name: str, user_ids: Optional[List[str]] = None) -> Group:
        """Create a new group of users.

        Args:
            name: name of the group
            user_ids: user identifiers to add to the group.

        Raises:
            ValueError: if the group already exists
        """
        user_ids = user_ids or []
        user_emails = [self.get_user(id_).email for id_ in user_ids]
        if name in self.group_names:
            raise ValueError(f"The group {name} already exists.")

        new_group = Group(name=name, users=user_emails)
        self.groups.append(new_group)
        self.save()
        return new_group

    @property
    def group_names(self) -> List[str]:
        """Return the names of the groups in the authentication store."""
        return [group.name for group in self.groups]

    @property
    def user_names(self) -> List[str]:
        """Return the names of the users in the authentication store."""
        return [user.name for user in self.users]

    @property
    def config_file(self) -> str:
        """Return the path to the config file."""
        return str(self._config_file)

    @property
    def store_dir(self) -> Path:
        """Return the path to the store directory."""
        return Path(self.config_file).parent

    def reload(self) -> None:
        """Reload the contents of the authentication store."""
        self.load(self.config_file)

    def load(self, filename: Optional[str] = None) -> None:
        """Load a configuration file."""
        if not filename:
            filename = f"{self.store_dir}/.auth.yaml"
        self._check_auth_file(filename)
        super().load(self.config_file)
        self._load_gpg_id_files()

    def _check_auth_file(self, filename: str) -> Path:
        """Return the AuthStore configuration file.

        If the file doesn't exist it will copy the default template.
        """
        config_file = Path(filename).expanduser()
        self._config_file = str(config_file)

        if not config_file.exists():
            self.save()

        return config_file

    def _load_gpg_id_files(self) -> None:
        """Load the data of the gpg-id files that is not already in the access store."""
        for gpg_id in self.store_dir.rglob(".gpg-id"):
            access = self.gpg_id_access_key(gpg_id)
            try:
                existent_keys = self.access_keys(access)
                for key in gpg_id.read_text().splitlines():
                    if key not in existent_keys:
                        self.access[access].append(key)
            except KeyError:
                self.access[access] = gpg_id.read_text().splitlines()

    def save(self) -> None:
        """Save the contents of the authentication store."""
        with open(self.config_file, "w+", encoding="utf-8") as file_cursor:
            yaml = YAML()
            yaml.default_flow_style = False
            yaml.dump(self.dict(), file_cursor)

    def get_group(self, name: str) -> Tuple[Group, List[User]]:
        """Return the group that matches the group name.

        Raises:
            NotFoundError: if no group matches the identifier
        """
        group_match = [group for group in self.groups if group.name == name]

        if len(group_match) == 0:
            raise NotFoundError(f"There is no group that matches {name}.")
        if len(group_match) > 1:
            raise TooManyError(
                f"More than one group matched the selected criteria {name}."
            )

        group = group_match[0]
        users = [self.get_user(id_) for id_ in group.users]

        return group, users

    def get_user(self, identifier: Identifier) -> User:
        """Return the user that matches the user identifier.

        Args:
            identifier: string that identifies the user. It can be either the name,
                the email or the gpg key.

        Raises:
            NotFoundError: if no user matches the identifier
            TooManyError: if more than one user matches the identifier
        """
        user_match = [user for user in self.users if user.match(identifier)]

        if len(user_match) == 0:
            raise NotFoundError(f"There is no user that matches {identifier}.")
        if len(user_match) == 1:
            return user_match[0]
        raise TooManyError(
            f"More than one user matched the selected criteria {identifier}."
        )

    def get_identifier(self, identifier: Identifier) -> Union[Group, User]:
        """Return the group or user that matches the identifier.

        Args:
            identifier: string that identifies the user or group. It can be
                either the name, the email or the gpg key.

        Raises:
            NotFoundError: if no user or group matches the identifier
            TooManyError: if more than one user or group matches the identifier
        """
        # users
        user = None
        with suppress(NotFoundError):
            user = self.get_user(identifier)

        # new groups
        with suppress(NotFoundError):
            group, _ = self.get_group(identifier)
            if user:
                raise TooManyError(
                    f"Both user {user.name} and group {group.name} "
                    f"matched identifier {identifier}, "
                    "cancelling authorization."
                )
            return group
        if user:
            return user
        raise NotFoundError(
            f"No user or group (or more than one) matches identifier {identifier}"
        )

    def find_keys(self, identifier: Identifier) -> List["GPGKey"]:
        """Return the gpg keys that matches the identifier.

        Args:
            identifier: string that identifies a user or group. It can be either the
                name, the email or the gpg key.
        """
        users = []

        # Find in the users
        with suppress(NotFoundError):
            users.append(self.get_user(identifier))

        # Find in the groups
        with suppress(NotFoundError):
            _, group_users = self.get_group(identifier)
            users.extend(group_users)

        return [user.key for user in users]

    def change_group_users(
        self,
        group_name: str,
        add_identifiers: Optional[List[Identifier]] = None,
        remove_identifiers: Optional[List[Identifier]] = None,
    ) -> bool:
        """Change the list of users of an existent group.

        Args:
            group_name: Group to change
            add_identifiers: Unique identifier of a user to add. It can be the
                user name, email or gpg key.
            remove_identifiers: Unique identifier of a user to remove. It can
                be the user name, email or gpg key.

        Returns:
            If there has been applied any change in the auth store
        """
        add_identifiers = add_identifiers or []
        remove_identifiers = remove_identifiers or []
        group, _ = self.get_group(group_name)

        log.debug("Add users")
        users_to_add = [self.get_user(id_) for id_ in add_identifiers]
        added_users = group.add_users(users=users_to_add)

        log.debug("Remove users")
        users_to_remove = [self.get_user(id_) for id_ in remove_identifiers]
        removed_users = group.remove_users(users=users_to_remove)

        log.debug("Remove duplicate information in the access storage")
        for access_entry in self.access.values():
            # If the group we want to change is part of an access entry
            if group.name in access_entry:
                # And if any of the rest of the ids match a user that we have
                # added or removed
                for id_ in access_entry.copy():
                    for user in users_to_add + users_to_remove:
                        if user.match(id_):
                            # Then we can remove that entry from the access
                            # storage as it's already tracked by the group
                            access_entry.remove(id_)
                            break

        self.save()

        if added_users or removed_users:
            return True
        return False

    def change_access(
        self,
        gpg_id: GPGIDPath,
        add_identifiers: Optional[List[Identifier]] = None,
        remove_identifiers: Optional[List[Identifier]] = None,
        ignore_parent: bool = False,
    ) -> bool:
        """Authorize or revoke a group or person to a directory of the password store.

        It will store the access information in the auth store.

        Args:
            gpg_id: path to a passwordstore .gpg-id file
            add_identifiers: Unique identifiers of groups or people to authorize.
                It can be the group name, person name, email or gpg key.
            remove_identifiers: Unique identifiers of groups or people to revoke.
                It can be the group name, person name, email or gpg key.
            ignore_parent: Ignore the access permissions defined in the parent .gpg-id.
                It shouldn't be True by default because it will risk locking
                yourself out.

        Returns:
            Whether a change was made.
        """
        add_identifiers = add_identifiers or []
        remove_identifiers = remove_identifiers or []

        try:
            access = self.access[self.gpg_id_access_key(gpg_id)]
        except KeyError:
            # If the access doesn't exist it will take it's parent as a base
            if not ignore_parent:
                access = self.access[
                    self.gpg_id_access_key(self.gpg_id_file(Path(gpg_id).parent))
                ].copy()
            else:
                access = []

        original_access = access.copy()

        log.debug("Authorize new access")
        for identifier in add_identifiers:
            access = self._authorize_access(identifier, access, gpg_id)

        log.debug("Revoke existing access")
        for identifier in remove_identifiers:
            access = self._revoke_access(identifier, access)

        if access == original_access:
            return False

        self.access[self.gpg_id_access_key(gpg_id)] = access
        self.save()

        return True

    def _authorize_access(
        self, identifier: Identifier, access: List[str], gpg_id: GPGIDPath
    ) -> List[str]:
        """Authorize a new element into an access list.

        Args:
            identifier: Unique identifier of a group or person to authorize.
                It can be the group name, person name, email or gpg key.
            access: the value of an entry of self.access

        Returns:
            updated access with the new element
        """
        new_access = self.get_identifier(identifier)

        if any(self.get_identifier(element).match(new_access) for element in access):
            log.info(
                f"{new_access.name} is already authorized to access "
                f"{gpg_id}, skipping"
            )
            return access
        if isinstance(new_access, User):
            log.info(
                f"  Authorizing access to user {new_access.name}: "
                f"{new_access.email} ({new_access.key})"
            )
        else:
            log.info(f"  Authorizing access to group {new_access.name}")
            log.debug(
                "  Removing the gpg keys that are already tracked by the "
                "group we're adding"
            )
            _, users = self.get_group(identifier)
            for element in access:
                if any(user.match(element) for user in users):
                    log.debug(
                        f"{element} is already included in {identifier} "
                        "removing it from the access entry"
                    )
                    access.remove(element)

        access.append(new_access.name)

        return access

    def _revoke_access(self, identifier: Identifier, access: List[str]) -> List[str]:
        """Revoke an element from an access list.

        Args:
            identifier: Unique identifier of a group or person to revoke.
                It can be the group name, person name, email or gpg key.
            access: the value of an entry of self.access

        Returns:
            updated access without the matching element
        """
        revoke = self.get_identifier(identifier)

        if isinstance(revoke, User):
            log.info(
                f"  Revoking access to user {revoke.name}: "
                f"{revoke.email} ({revoke.key})"
            )
        else:
            log.info(f"  Revoking access to group {revoke.name}")

        # We may pass here when we remove the access of a user to a group,
        # therefore the access to the directory doesn't change as it's
        # binded to the group
        with suppress(ValueError):
            access.remove(revoke.name)

        return access

    def has_access(self, path: Path, identifier: "Identifier") -> bool:
        """Check in the stored access if the identdifier is allowed to the gpg_id file.

        Args:
            path: A real path to an element of the pass store.
            identifier: user or group identifier
        """
        authoree = self.get_identifier(identifier)
        access = self.access[self.gpg_id_access_key(self.gpg_id_file(path))]

        if isinstance(authoree, Group):
            return authoree.name in access

        for id_ in access:
            authorized = self.get_identifier(id_)
            if authorized == authoree:
                return True
            if isinstance(authorized, Group):
                for user_id in authorized.users:
                    if self.get_user(user_id) == authoree:
                        return True
        return False

    def allowed_keys(
        self,
        gpg_id: GPGIDPath,
    ) -> List[GPGKey]:
        """Return the allowed gpg keys of a gpg-id path.

        Args:
            gpg_id: path to a .gpg_id file

        Raises:
            NotFoundError: If there is no data of that gpg-id file.
        """
        try:
            authorees = self.access[self.gpg_id_access_key(gpg_id)]
        except KeyError as error:
            raise NotFoundError(
                f"There is no access information for the gpg-id file {gpg_id}"
            ) from error

        keys = []
        for authoree in authorees:
            if len(authoree) == 40:
                # authoree is a gpg_id key
                keys.append(authoree)
            else:
                keys.extend(self.find_keys(authoree))

        return keys

    def gpg_id_file(self, path: Union[Path, str]) -> Path:
        """Return the first .gpg-id file that applies to a path.

        Args:
            path: A real path to an element of the pass store.
        """
        if isinstance(path, str):
            path = Path(path)

        if path.match("*.gpg-id"):
            return path

        if path.is_file():
            path = path.parent

        gpg_id_path = path / ".gpg-id"

        if gpg_id_path.is_file():
            return gpg_id_path

        if path == self.store_dir:
            raise NotFoundError("Couldn't find the root .gpg-id of your store")

        return self.gpg_id_file(path.parent)

    def gpg_id_access_key(self, gpg_id: Union[Path, str]) -> str:
        """Return the key of the access property for the .gpg-id file.

        It returns the relative path from self.store_dir so that different users
        can use the same .auth.yaml file

        Args:
            gpg_id: A real path to a .gpg_id file.

        Raises:
            ValueError: if the gpg_id path is not part of the store_dir
        """
        if isinstance(gpg_id, str):
            gpg_id = Path(gpg_id)

        return str(gpg_id.relative_to(self.store_dir))

    def access_keys(self, access_id: str) -> List[GPGKey]:
        """Return the GPG keys allowed to an access entry.

        Args:
            access_id: identifier of an access element
        """
        keys: List[GPGKey] = []

        for access in self.access[access_id]:
            authoree = self.get_identifier(access)
            if isinstance(authoree, Group):
                _, users = self.get_group(access)
                keys.extend(user.key for user in users)
            else:
                keys.append(authoree.key)

        return list(set(keys))
