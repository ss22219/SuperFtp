namespace SuperFtp
{
    using System;

    public class BRE
    {
        public string regex;

        public BRE(string regex)
        {
            this.regex = regex;
        }

        public bool IsMatch(string input)
        {
            if (input == null)
            {
                return false;
            }
            int startIndex = 0;
            for (int i = 0; i < this.regex.Length; i++)
            {
                if ((this.regex[i] != '*') && (input[startIndex] != this.regex[i]))
                {
                    return false;
                }
                if (this.regex[i] == '*')
                {
                    int length = this.regex.Substring(i).Replace("*", string.Empty).Length;
                    if (length == 0)
                    {
                        return true;
                    }
                    if (length <= (input.Length - startIndex))
                    {
                        for (int j = 0; startIndex < input.Length; j++)
                        {
                            if (new BRE(this.regex.Substring(i + 1)).IsMatch(input.Substring(startIndex)))
                            {
                                return true;
                            }
                            startIndex++;
                        }
                    }
                    return false;
                }
                startIndex++;
            }
            return startIndex == input.Length;
        }
    }
}

