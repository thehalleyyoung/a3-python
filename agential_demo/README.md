# agential_demo

Demo showing how to include the local `a3_python` package in an agential workflow.

Run the demo:

```bash
python3 agential_demo/demo.py
```

The demo script prepends the workspace root to `sys.path` so the local `a3_python`
package can be imported without installing it into the environment.
