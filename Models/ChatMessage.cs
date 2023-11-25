using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FormulaOneApp.Models
{
    public class ChatMessage
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public DateTime Timestamp { get; set; }
        public string SkinTone { get; set; }
        public string MBTI { get; set; }
        public string ChatName { get; set; }
        public string KeyWord { get; set; }

        [NotMapped]
        public string[] KeyWords
        {
            get { return KeyWord.Split(';'); }
            set { KeyWord = String.Join(";", value); }
        }
    }
}
