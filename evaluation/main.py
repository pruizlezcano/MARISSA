import typer

from evaluation.ResultsEvaluator import ResultsEvaluator

app = typer.Typer(
    name="main",
    help="MARISSA results evaluation",
    invoke_without_command=True,
    add_completion=False,
)


@app.callback()
def main(
    resutls_file: str = typer.Option(
        ...,  # Required
        "--input",
        "-i",
        help="The results .csv file to read",
    ),
):

    analyzer = ResultsEvaluator(resutls_file)
    analyzer.analyze()


if __name__ == "__main__":
    app()
