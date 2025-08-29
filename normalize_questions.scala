import java.io.{File, PrintWriter}
import java.text.Normalizer

object NormalizeQuestions {

  // French stop words list
  val frenchStopWords: Set[String] = Set(
    "au",
    "aux",
    "avec",
    "ce",
    "ces",
    "dans",
    "de",
    "des",
    "du",
    "elle",
    "en",
    "et",
    "eux",
    "il",
    "je",
    "la",
    "le",
    "leur",
    "lui",
    "ma",
    "mais",
    "me",
    "même",
    "mes",
    "moi",
    "mon",
    "ne",
    "nos",
    "notre",
    "nous",
    "on",
    "ou",
    "par",
    "pas",
    "pour",
    "qu",
    "que",
    "sa",
    "se",
    "ses",
    "son",
    "sur",
    "ta",
    "te",
    "tes",
    "toi",
    "ton",
    "tu",
    "un",
    "une",
    "vos",
    "votre",
    "vous",
    "c",
    "d",
    "j",
    "l",
    "à",
    "m",
    "n",
    "s",
    "t",
    "y",
    "été",
    "étée",
    "étées",
    "étés",
    "étant",
    "étante",
    "étants",
    "étantes",
    "suis",
    "es",
    "est",
    "sommes",
    "êtes",
    "sont",
    "serai",
    "seras",
    "sera",
    "serons",
    "serez",
    "seront",
    "serais",
    "serait",
    "serions",
    "seriez",
    "seraient",
    "étais",
    "était",
    "étions",
    "étiez",
    "étaient",
    "fus",
    "fut",
    "fûmes",
    "fûtes",
    "furent",
    "sois",
    "soit",
    "soyons",
    "soyez",
    "soient",
    "fusse",
    "fusses",
    "fût",
    "fussions",
    "fussiez",
    "fussent",
    "ayant",
    "ayante",
    "ayantes",
    "ayants",
    "eu",
    "eue",
    "eues",
    "eus",
    "ai",
    "as",
    "avons",
    "avez",
    "ont",
    "aurai",
    "auras",
    "aura",
    "aurons",
    "aurez",
    "auront",
    "aurais",
    "aurait",
    "aurions",
    "auriez",
    "auraient",
    "avais",
    "avait",
    "avions",
    "aviez",
    "avaient",
    "eut",
    "eûmes",
    "eûtes",
    "eurent",
    "aie",
    "aies",
    "ait",
    "ayons",
    "ayez",
    "aient",
    "eusse",
    "eusses",
    "eût",
    "eussions",
    "eussiez",
    "eussent"
  ).map(normalizeString)

  // Normalize string but keep stop words
  def normalizeString(str: String): String = {
    val normalized = Normalizer.normalize(str, Normalizer.Form.NFD)
    val stripped = normalized.replaceAll("\\p{InCombiningDiacriticalMarks}+", "").toLowerCase()
    stripped.replaceAll("[^a-z0-9\\s'-]", "").trim
  }

  // Remove stop words for comparison
  def removeStopWords(text: String): String = {
    text
      .split("\\s+")
      .filterNot(word => frenchStopWords.contains(word))
      .mkString(" ")
      .replaceAll("\\s+", " ")
      .trim
  }

  def main(args: Array[String]): Unit = {
    val inputFile = new File("questions.txt")
    val outputFile = new File("normalized_questions.txt")

    if (!inputFile.exists()) {
      println(s"Error: Input file '${inputFile.getPath}' does not exist")
      System.exit(1)
    }

    val lines = scala.io.Source.fromFile(inputFile).getLines().toList

    // Normalize all lines
    val normalizedLines = lines.map(normalizeString)

    // Create a map of (withoutStopWords -> originalNormalized) and then take unique values
    val uniqueQuestions = normalizedLines
      .map(question => (removeStopWords(question), question))
      .groupBy(_._1) // Group by the version without stop words
      .values // Get the groups
      .map(_.head._2) // Take the first original question from each group
      .toList
      .sorted

    val writer = new PrintWriter(outputFile)
    try {
      uniqueQuestions.foreach(writer.println)
      println(s"Successfully wrote ${uniqueQuestions.size} unique questions (after stop words removal) to '${outputFile.getPath}'")
      println(s"Original lines: ${lines.size}, After normalization: ${normalizedLines.distinct.size}, After stop words removal: ${uniqueQuestions.size}")
    } finally {
      writer.close()
    }
  }
}
