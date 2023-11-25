namespace FormulaOneApp.Controllers
{
    using FormulaOneApp.Data;
    using FormulaOneApp.Models;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    [ApiController]
    [Route("api/[controller]")]
    public class ChatController : ControllerBase
    {
        private readonly AppDbContext _context;

        public ChatController(AppDbContext context)
        {
            _context = context;
        }

        [HttpPost]
        public async Task<ActionResult<ChatMessage>> PostChatMessage(ChatMessage message)
        {
            int userChatCount = await _context.ChatMessages.CountAsync(m => m.UserId == message.UserId);
            message.ChatName = "Chat" + (userChatCount + 1);

            _context.ChatMessages.Add(message);
            await _context.SaveChangesAsync();
            return Ok(message);
        }

        [HttpGet("{userId}")]
        public async Task<ActionResult<IEnumerable<ChatMessage>>> GetAllChatMessages(string userId)
        {
            var userChatMessages = await _context.ChatMessages.Where(m => m.UserId == userId).ToListAsync();
            return userChatMessages;
        }


        [HttpGet("{Id}/{userId}")]
        public async Task<ActionResult<ChatMessage>> GetChatMessages(string userId, int Id)
        {
            var message = await _context.ChatMessages.FirstOrDefaultAsync(m => m.UserId == userId && m.Id == Id);
            if (message == null)
            {
                return NotFound();
            }
            return message;
        }


        [HttpDelete("{userId}")]
        public async Task<IActionResult> DeleteAllChatMessages(string userId)
        {
            var userChatMessages = _context.ChatMessages.Where(m => m.UserId == userId);
            _context.ChatMessages.RemoveRange(userChatMessages);
            await _context.SaveChangesAsync();
            return NoContent();
        }


        [HttpDelete("{Id}/{userId}")]
        public async Task<IActionResult> DeleteChatMessages(string userId, int Id)
        {
            var userChatMessages = await _context.ChatMessages.Where(m => m.UserId == userId && m.Id == Id).ToListAsync();
            if (userChatMessages.Any())
            {
                _context.ChatMessages.RemoveRange(userChatMessages);
                await _context.SaveChangesAsync();
                return NoContent();
            }

            return NotFound();
        }
    }
}
