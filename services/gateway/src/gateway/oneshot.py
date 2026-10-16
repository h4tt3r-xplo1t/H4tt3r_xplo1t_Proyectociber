"""What the one-shot operator commands share: destroying their seeded secret.

`gateway.bootstrap` and `gateway.breakglass` each read one KV v2 secret that the
responsible person seeded, and must destroy every version of it in the same step
that applies its effect. The destroy has three outcomes, and the commands treat
them differently: it worked (the key no longer reads), OpenBao refused it
(nothing was deleted), or it may have applied without a definite answer.
"""

import hvac

from gateway.secrets import KV_MOUNT

# OpenBao answered the delete with a 4xx: it refused, nothing was deleted.
DEFINITE_REJECTIONS = (
    hvac.exceptions.InvalidRequest,
    hvac.exceptions.Unauthorized,
    hvac.exceptions.Forbidden,
    hvac.exceptions.InvalidPath,
    hvac.exceptions.PreconditionFailed,
    hvac.exceptions.RateLimitExceeded,
)


class DestroyError(RuntimeError):
    """Base of the two ways the destroy step can fail; never raised itself."""


class DestroyFailed(DestroyError):
    """The secret could not be destroyed or still answers a read."""


class DestroyUncertain(DestroyError):
    """The delete may have applied, but OpenBao gave no definite answer."""


def destroy_secret(client, path: str) -> None:
    """Delete the key with all its versions and prove that it no longer reads."""
    try:
        client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=path, mount_point=KV_MOUNT
        )
    except DEFINITE_REJECTIONS:
        raise DestroyFailed from None
    except Exception:
        # A 5xx or a transport failure may come after the delete was applied.
        raise DestroyUncertain from None
    try:
        client.secrets.kv.v2.read_secret_version(
            path=path, mount_point=KV_MOUNT, raise_on_deleted_version=True
        )
    except hvac.exceptions.InvalidPath:
        return
    except Exception:
        # The delete was accepted and the read gave no answer: it may be gone.
        raise DestroyUncertain from None
    raise DestroyFailed
