// -------------------------------------------------
// -------------------- Master ---------------------
// -------------------------------------------------

function DebugMessage(message) {
   console.log(message);
}

// small uart device
function UARTDev() {
   this.inputChar = 0;

   this.ReceiveChar = function(c) {
      console.log("Term input = " + c);
      this.inputChar = c;
   };

   this.ReadChar = function() {
      return this.inputChar;
   };

   this.ClearChar = function() {
      this.inputChar = 0;
   };
}

function moxieGUI(termid)
{
   this.term = new Terminal(24, 80, termid);
   this.uart = new UARTDev();
   this.terminput = new TerminalInput(this.uart);

   document.onkeypress = function(event) {
      return this.terminput.OnKeyPress(event);      
   }.bind(this);

   document.onkeydown = function(event) {
      //DebugMessage("" + event.keyCode);
      return this.terminput.OnKeyDown(event);
   }.bind(this);

   document.onkeyup = function(event) {
      return this.terminput.OnKeyUp(event);
   }.bind(this);

}
