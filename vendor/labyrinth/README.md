# Labyrinth probe attribution

The files in `core/probe/` are adapted from
[Labyrinth](https://github.com/dotnetdork/Labyrinth), revision
`e316b3f99cdc809eb18d02c68f7ece3c7c3cd8f5`, by Jay Sausa.
They retain the upstream [license](LICENSE). The owner has granted written
permission to import the adapted code into helperbro.

The adaptations remove runner-specific service-list functions and the insecure
HTTPS fallback, require certificate verification, bypass proxy settings for
explicit targets, and bound curl response size. The helperbro entry points
validate input and expose pass/fail/unknown exit status.
